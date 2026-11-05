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
