// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading a `wg-quick` profile and writing the NetworkManager keyfile for it.

use super::*;

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Peer {
    pub(crate) public_key: String,
    pub(crate) preshared_key: Option<String>,
    pub(crate) allowed_ips: Vec<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) keepalive: Option<u16>,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Profile {
    pub(crate) private_key: String,
    pub(crate) addresses: Vec<String>,
    pub(crate) dns: Vec<String>,
    pub(crate) dns_search: Vec<String>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) mtu: Option<u16>,
    pub(crate) fwmark: Option<String>,
    pub(crate) peers: Vec<Peer>,
}

pub(crate) fn is_key(text: &str) -> bool {
    text.len() == 44
        && text.ends_with('=')
        && text[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

pub(crate) fn is_network(text: &str) -> bool {
    let (addr, len) = text.split_once('/').unwrap_or((text, ""));
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    len.is_empty() || len.parse::<u8>().is_ok_and(|l| l <= max)
}

/// `IP:PORT` or `[IPv6]:PORT`, or `host:port` for a name.
pub(crate) fn split_endpoint(text: &str) -> Option<(String, u16)> {
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

pub(crate) fn parse_profile(text: &str) -> Result<Profile, String> {
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
pub(crate) fn valid_name(name: &str) -> bool {
    (1..=10).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

pub(crate) fn uuid_for(name: &str) -> String {
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

pub(crate) fn keyfile(name: &str, interface: &str, profile: &Profile) -> String {
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
