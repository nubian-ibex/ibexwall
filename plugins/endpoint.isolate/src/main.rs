// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `endpoint.isolate`: emergency mode. Two owned chains (input and output,
//! ahead of every other table) accept loopback and an allow list and drop
//! the rest, and a marker file says it is on, so the check can tell the
//! person. The plan is a network change: the engine asks for a confirmation
//! and reverts it if nobody confirms. Turning it off is the transaction's
//! rollback (History), which removes the chains and the marker and nothing
//! else; the plugin has no "off" plan because an emptied chain would stay
//! behind.
//!
//! The allow list is addresses or networks. With `ports` set, new
//! connections to (or from) them are limited to those ports; replies of
//! connections already established with them always pass, so an SSH session
//! that is allowed keeps working in both directions.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Hook, Proto, Rule, Verdict};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

const MARKER: &str = "/etc/ibexwall/isolate/active.json";
/// Ahead of the other IbexWall chains and the distro's firewall.
const PRIORITY: i32 = -300;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Isolate)) {
        eprintln!("ibexwall-plugin-isolate: {err}");
        std::process::exit(1);
    }
}

struct Isolate;

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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    #[serde(deserialize_with = "many")]
    allow: Vec<String>,
    #[serde(deserialize_with = "many")]
    ports: Vec<String>,
    /// Required to cut the machine off completely (an empty allow list).
    #[serde(deserialize_with = "flexible_bool")]
    lockdown: bool,
}

impl Plugin for Isolate {
    fn id(&self) -> &'static str {
        "endpoint.isolate"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&config)
    }
}

/// `22/tcp`, `51820/udp`, or `22` (tcp).
fn parse_port(text: &str) -> Result<(Proto, u16), PluginError> {
    let (port, proto) = text.split_once('/').unwrap_or((text, "tcp"));
    let proto = match proto.to_ascii_lowercase().as_str() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => {
            return Err(PluginError::invalid(
                "ports",
                format!("`{text}`: the protocol is tcp or udp"),
            ));
        }
    };
    match port.trim().parse::<u16>() {
        Ok(port) if port != 0 => Ok((proto, port)),
        _ => Err(PluginError::invalid(
            "ports",
            format!("`{text}` is not a port between 1 and 65535"),
        )),
    }
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

fn plan(config: &Config) -> Result<Vec<Op>, PluginError> {
    if config.allow.is_empty() && !config.lockdown {
        return Err(PluginError::invalid(
            "allow",
            "an empty allow list cuts this computer off completely; name the addresses to keep, or set lockdown=true",
        ));
    }
    let mut ports: BTreeMap<u8, Vec<u16>> = BTreeMap::new();
    for text in &config.ports {
        let (proto, port) = parse_port(text)?;
        ports
            .entry(if proto == Proto::Tcp { 0 } else { 1 })
            .or_default()
            .push(port);
    }

    let mut out = vec![rule(|r| {
        r.oif_loopback = true;
    })];
    let mut inbound = vec![rule(|r| {
        r.iif_loopback = true;
    })];
    if !config.allow.is_empty() {
        // Replies on connections that already exist with an allowed peer.
        out.push(rule(|r| {
            r.ct_established = true;
            r.daddr = config.allow.clone();
        }));
        inbound.push(rule(|r| {
            r.ct_established = true;
            r.saddr = config.allow.clone();
        }));
        if ports.is_empty() {
            out.push(rule(|r| r.daddr = config.allow.clone()));
            inbound.push(rule(|r| r.saddr = config.allow.clone()));
        } else {
            for (key, list) in &ports {
                let proto = if *key == 0 { Proto::Tcp } else { Proto::Udp };
                out.push(rule(|r| {
                    r.daddr = config.allow.clone();
                    r.protocols = vec![proto];
                    r.dports = list.clone();
                }));
                inbound.push(rule(|r| {
                    r.saddr = config.allow.clone();
                    r.protocols = vec![proto];
                    r.dports = list.clone();
                }));
            }
        }
    }
    let drop = |mut rules: Vec<Rule>| {
        rules.push(rule(|r| r.verdict = Verdict::Drop));
        rules
    };
    let fragment = Fragment {
        chains: vec![
            Chain {
                name: "endpoint_isolate_out".into(),
                priority: PRIORITY,
                hook: Hook::Output,
                rules: drop(out),
            },
            Chain {
                name: "endpoint_isolate_in".into(),
                priority: PRIORITY,
                hook: Hook::Input,
                rules: drop(inbound),
            },
        ],
    };
    fragment
        .validate()
        .map_err(|e| PluginError::invalid("allow", e.to_string()))?;
    let marker = serde_json::json!({ "allow": config.allow, "ports": config.ports });
    Ok(vec![
        Op::FileWrite {
            path: MARKER.into(),
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

fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let Some(text) = sandbox.read(MARKER) else {
        return CheckReport {
            results: vec![CheckResult {
                id: "isolate.state".into(),
                severity: Severity::Info,
                outcome: CheckOutcome::Pass,
            }],
            findings: vec![],
        };
    };
    let count = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v["allow"].as_array().map(Vec::len))
        .unwrap_or(0);
    let mut args = BTreeMap::new();
    args.insert("count".to_string(), count.to_string());
    CheckReport {
        results: vec![CheckResult {
            id: "isolate.state".into(),
            severity: Severity::Info,
            outcome: CheckOutcome::Fail,
        }],
        findings: vec![Finding {
            id: "isolate.active".into(),
            plugin: "endpoint.isolate".into(),
            severity: Severity::Info,
            title_key: "isolate-active-title".into(),
            summary_key: "isolate-active-summary".into(),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: Value) -> Config {
        serde_json::from_value(value).unwrap()
    }

    fn fragment(ops: &[Op]) -> Fragment {
        match &ops[1] {
            Op::NftFragment { fragment } => serde_json::from_value(fragment.clone()).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_allow_list_is_refused_unless_lockdown_is_said() {
        assert!(plan(&config(json!({}))).is_err());
        let ops = plan(&config(json!({ "lockdown": true }))).unwrap();
        let f = fragment(&ops);
        // Loopback, then drop, on both chains: nothing else.
        assert!(f.chains.iter().all(|c| c.rules.len() == 2));
        assert_eq!(f.chains[0].rules[1].verdict, Verdict::Drop);
        assert!(plan(&config(json!({ "lockdown": "true" }))).is_ok());
    }

    #[test]
    fn the_allow_list_passes_replies_and_the_rest_is_dropped() {
        let ops = plan(&config(json!({ "allow": ["10.0.2.2", "192.168.1.0/24"] }))).unwrap();
        let f = fragment(&ops);
        let out = &f.chains[0];
        assert_eq!(out.hook, Hook::Output);
        assert_eq!(out.priority, PRIORITY);
        assert!(out.rules[0].oif_loopback);
        assert!(out.rules[1].ct_established && out.rules[1].daddr.len() == 2);
        assert!(out.rules[2].daddr.len() == 2 && !out.rules[2].ct_established);
        assert_eq!(out.rules.last().unwrap().verdict, Verdict::Drop);
        let inbound = &f.chains[1];
        assert_eq!(inbound.hook, Hook::Input);
        assert_eq!(inbound.rules[1].saddr, ["10.0.2.2", "192.168.1.0/24"]);
    }

    #[test]
    fn ports_limit_new_connections_but_not_replies() {
        let ops = plan(&config(
            json!({ "allow": "10.0.2.2", "ports": ["22/tcp", 443, "51820/udp"] }),
        ))
        .unwrap();
        let out = &fragment(&ops).chains[0];
        assert!(out.rules[1].ct_established && out.rules[1].dports.is_empty());
        let limited: Vec<_> = out.rules.iter().filter(|r| !r.dports.is_empty()).collect();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].dports, [22, 443]);
        assert_eq!(limited[1].protocols, [Proto::Udp]);
    }

    #[test]
    fn bad_input_is_refused_before_a_plan_exists() {
        for bad in [
            json!({ "allow": ["not-an-address"] }),
            json!({ "allow": ["10.0.0.0/40"] }),
            json!({ "allow": "10.0.2.2", "ports": ["0"] }),
            json!({ "allow": "10.0.2.2", "ports": ["22/icmp"] }),
            json!({ "allow": "10.0.2.2", "surprise": 1 }),
        ] {
            let parsed: Result<Config, _> = serde_json::from_value(bad.clone());
            let refused = match parsed {
                Err(_) => true,
                Ok(c) => plan(&c).is_err(),
            };
            assert!(refused, "{bad}");
        }
    }

    #[test]
    fn the_marker_makes_the_check_say_so() {
        let root = std::env::temp_dir().join(format!("ibx-iso-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/ibexwall/isolate")).unwrap();
        let sandbox = Sandbox::at(&root);
        assert!(evaluate(&sandbox, "now").findings.is_empty());
        std::fs::write(
            root.join("etc/ibexwall/isolate/active.json"),
            "{\"allow\":[\"a\",\"b\"]}",
        )
        .unwrap();
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings[0].args["count"], "2");
        std::fs::remove_dir_all(root).unwrap();
    }
}
