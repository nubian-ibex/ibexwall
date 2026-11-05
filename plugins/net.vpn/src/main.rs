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

mod killswitch;
mod openvpn;
mod wireguard;

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Hook, Proto, Rule, Verdict};
use killswitch::plan_killswitch;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wireguard::*;

const PROFILE_DIR: &str = "/etc/ibexwall/vpn/profiles";
const KILLSWITCH: &str = "/etc/ibexwall/vpn/killswitch.json";
const NM_DIR: &str = "/etc/NetworkManager/system-connections";
const DNS_DIR: &str = "/etc/ibexwall/dns";
/// Ahead of the other IbexWall chains and the distro's firewall.
const PRIORITY: i32 = -250;
const MAX_PROFILE: usize = 16 * 1024;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
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
mod tests;
