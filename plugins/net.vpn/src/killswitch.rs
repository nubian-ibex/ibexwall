// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kill switch: a chain that lets only the tunnel and the VPN server out.

use super::*;

pub(crate) fn rule(configure: impl FnOnce(&mut Rule)) -> Rule {
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

pub(crate) fn plan_killswitch(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let interfaces = if config.interfaces.is_empty() {
        vec!["wg".to_string(), "tun".to_string()]
    } else {
        config.interfaces.clone()
    };
    // Each server with the imported profile it came from, so an error can
    // name the profile to fix.
    let mut sourced: Vec<(String, Option<String>)> =
        config.endpoints.iter().map(|e| (e.clone(), None)).collect();
    for record in recorded(sandbox) {
        let name = record["name"].as_str().map(str::to_string);
        for endpoint in record["endpoints"].as_array().into_iter().flatten() {
            if let Some(text) = endpoint.as_str() {
                sourced.push((text.to_string(), name.clone()));
            }
        }
    }
    sourced.sort();
    sourced.dedup();
    let mut endpoints: Vec<String> = sourced.iter().map(|(e, _)| e.clone()).collect();
    endpoints.dedup();
    if endpoints.is_empty() {
        return Err(PluginError::invalid(
            "endpoints",
            "no VPN server is known: import a profile with IbexWall, or name the server as IP:PORT",
        ));
    }
    let mut server_rules = Vec::new();
    for (text, profile) in &sourced {
        let (host, port) = split_endpoint(text)
            .ok_or_else(|| PluginError::invalid("endpoints", format!("`{text}` is not IP:PORT")))?;
        if host.parse::<std::net::IpAddr>().is_err() {
            let from = profile
                .as_ref()
                .map(|p| format!(" (imported profile `{p}`)"))
                .unwrap_or_default();
            return Err(PluginError::invalid(
                "endpoints",
                format!(
                    "`{host}`{from} is a name; the kill switch needs the server's address (resolving it here would be a leak). Give it as endpoints=IP:{port}"
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
        // Only the broadcast and link-local destinations a DHCP client
        // uses: an open udp 67/547 rule would let anything out to any host.
        rules.push(rule(|r| {
            r.daddr = [
                "255.255.255.255",
                "169.254.0.0/16",
                "ff02::1:2",
                "fe80::/10",
            ]
            .map(String::from)
            .to_vec();
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
    // Containers, VMs and hotspots send through FORWARD, not OUTPUT: let
    // only what goes into or comes back from the tunnel, plus the same
    // explicit allow list, and drop the rest.
    let mut forward = vec![];
    for prefix in &interfaces {
        forward.push(rule(|r| r.oif_prefix = Some(prefix.clone())));
        forward.push(rule(|r| r.iif_prefix = Some(prefix.clone())));
    }
    if !config.allow.is_empty() {
        forward.push(rule(|r| r.daddr = config.allow.clone()));
    }
    forward.push(rule(|r| r.verdict = Verdict::Drop));
    let fragment = Fragment {
        chains: vec![
            Chain {
                name: "net_vpn_out".into(),
                priority: PRIORITY,
                hook: Hook::Output,
                rules,
            },
            Chain {
                name: "net_vpn_fwd".into(),
                priority: PRIORITY,
                hook: Hook::Forward,
                rules: forward,
            },
        ],
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
