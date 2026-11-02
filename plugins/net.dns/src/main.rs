// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.dns`: secure DNS through the local resolver (`ibexwall-dns`).
//!
//! The plugin reads the machine, detects its DNS stack and proposes typed
//! operations; the core snapshots, applies and, if needed, rolls them
//! back. Nothing here writes to the system.

mod backend;
mod presets;

use std::collections::BTreeMap;

use backend::Backend;
use ibexwall_dns::config::{Server, Settings, Transport, default_listen};
use ibexwall_dns::lists::ListRef;
use ibexwall_dns::policy::BlockResponse;
use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction, names,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Proto, Rule, Verdict};
use serde::Deserialize;
use serde_json::Value;

const ID: &str = "net.dns";
const SERVICE: &str = "ibexwall-dns.service";
const RESOLVED: &str = "systemd-resolved.service";
const CHECK_ID: &str = "dns.secure_resolver";

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(SecureDns)) {
        eprintln!("ibexwall-plugin-dns: {err}");
        std::process::exit(1);
    }
}

/// What the user chose, as the UI and CLI send it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    provider: String,
    transport: Transport,
    /// Custom upstreams; when present they replace the provider.
    servers: Vec<Server>,
    lists: Vec<ListRef>,
    block_response: BlockResponse,
    block_doh: bool,
    allow: Vec<String>,
    /// Refuse clear DNS (port 53) and DoT (port 853) from everyone but
    /// the resolver.
    enforcement: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: "quad9".into(),
            transport: Transport::Tls,
            servers: vec![],
            lists: vec![],
            block_response: BlockResponse::default(),
            block_doh: true,
            allow: vec![],
            enforcement: true,
        }
    }
}

impl Config {
    fn parse(value: Value) -> Result<Self, PluginError> {
        if value.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(value).map_err(|e| PluginError::invalid("config", e.to_string()))
    }

    fn upstreams(&self) -> Result<Vec<Server>, PluginError> {
        if !self.servers.is_empty() {
            return Ok(self.servers.clone());
        }
        let provider = presets::provider(&self.provider).ok_or_else(|| {
            PluginError::invalid("provider", format!("unknown `{}`", self.provider))
        })?;
        provider.servers(self.transport).ok_or_else(|| {
            PluginError::invalid(
                "transport",
                format!("{} does not document {:?}", provider.name, self.transport),
            )
        })
    }

    fn settings(&self) -> Result<Settings, PluginError> {
        for list in &self.lists {
            list.resolve()
                .map_err(|e| PluginError::invalid("lists", e.to_string()))?;
        }
        Ok(Settings {
            listen: default_listen(),
            servers: self.upstreams()?,
            block_response: self.block_response,
            block_doh: self.block_doh,
            block: vec![],
            allow: self.allow.clone(),
            doh_endpoints: vec![],
            lists: self.lists.clone(),
            update_interval_hours: 24,
        })
    }
}

struct SecureDns;

impl Plugin for SecureDns {
    fn id(&self) -> &'static str {
        ID
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system()))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        plan(&Sandbox::system(), Config::parse(config)?)
    }

    async fn verify(&self, _transaction: &str, _ops: &[Op]) -> bool {
        evaluate(&Sandbox::system())
            .results
            .iter()
            .all(|r| r.outcome == CheckOutcome::Pass)
    }
}

fn dropin_content() -> String {
    // FallbackDNS= (empty) removes resolved's built-in plain-text public
    // servers, so a dead local resolver can never leak queries.
    format!(
        "# Managed by IbexWall (net.dns). Remove this file to restore the previous behavior.\n\
         [Resolve]\nDNS={}\nDomains=~.\nFallbackDNS=\n",
        names::DNS_BIND_ADDR
    )
}

fn plan(sandbox: &Sandbox, config: Config) -> Result<Vec<Op>, PluginError> {
    match backend::detect(sandbox) {
        Backend::Resolved => {}
        Backend::Unsupported(reason) => return Err(PluginError::invalid("backend", reason)),
    }
    let settings = config.settings()?;
    let settings_json = serde_json::to_string_pretty(&settings)
        .map_err(|e| PluginError::invalid("settings", e.to_string()))?;
    let settings_path = names::config_dir()
        .join("dns")
        .join("resolver.json")
        .to_string_lossy()
        .into_owned();
    let write = |path: String, content: String| Op::FileWrite {
        path,
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![
        write(settings_path, format!("{settings_json}\n")),
        write(names::ARTIFACT_RESOLVED.into(), dropin_content()),
        // The resolver must be up before resolved is pointed at it.
        Op::SystemdUnit {
            unit: SERVICE.into(),
            action: UnitAction::Enable,
            now: Some(true),
        },
        Op::SystemdUnit {
            unit: RESOLVED.into(),
            action: UnitAction::Restart,
            now: None,
        },
    ];
    // Last, so a failure above can never leave clear DNS blocked with no
    // resolver to answer.
    if config.enforcement {
        ops.push(enforcement_op(sandbox)?);
    }
    Ok(ops)
}

/// Looks up a user's uid in `/etc/passwd` (read-only).
fn uid_of(sandbox: &Sandbox, user: &str) -> Option<u32> {
    sandbox.read("/etc/passwd")?.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(user)).then(|| fields.nth(1)?.parse().ok())?
    })
}

/// Refuse clear DNS and DoT from every user except the resolver. Loopback
/// stays open so applications can reach the local stub.
fn enforcement_op(sandbox: &Sandbox) -> Result<Op, PluginError> {
    let uid = uid_of(sandbox, names::DNS_USER).ok_or_else(|| {
        PluginError::invalid(
            "enforcement",
            format!("the `{}` user does not exist", names::DNS_USER),
        )
    })?;
    let guard = Fragment {
        chains: vec![Chain {
            name: names::DNS_NFT_CHAIN.into(),
            priority: 0,
            rules: vec![
                Rule {
                    oif_loopback: true,
                    uid_not: None,
                    protocols: vec![],
                    dports: vec![],
                    verdict: Verdict::Accept,
                },
                Rule {
                    oif_loopback: false,
                    uid_not: Some(uid),
                    protocols: vec![Proto::Udp, Proto::Tcp],
                    dports: vec![53, 853],
                    verdict: Verdict::Reject,
                },
            ],
        }],
    };
    Ok(Op::NftFragment {
        fragment: serde_json::to_value(guard)
            .map_err(|e| PluginError::invalid("enforcement", e.to_string()))?,
    })
}

/// `/proc/net/udp` lists a local address as little-endian hex.
fn listening_hex() -> String {
    let address: std::net::Ipv4Addr = names::DNS_BIND_ADDR
        .parse()
        .expect("DNS_BIND_ADDR is an IPv4 address");
    format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.octets()),
        names::DNS_BIND_PORT
    )
}

fn resolver_listening(sandbox: &Sandbox) -> bool {
    let wanted = listening_hex();
    sandbox.read("/proc/net/udp").is_some_and(|table| {
        table
            .lines()
            .any(|l| l.split_whitespace().nth(1) == Some(&wanted))
    })
}

fn dropin_points_at_resolver(sandbox: &Sandbox) -> bool {
    sandbox.read(names::ARTIFACT_RESOLVED).is_some_and(|text| {
        text.lines()
            .any(|l| l.trim() == format!("DNS={}", names::DNS_BIND_ADDR))
    })
}

/// Runs against any tree (real system, sandbox or fixture).
fn evaluate(sandbox: &Sandbox) -> CheckReport {
    let backend = backend::detect(sandbox);
    let outcome = match backend {
        Backend::Unsupported(_) => CheckOutcome::NotAssessed,
        Backend::Resolved if dropin_points_at_resolver(sandbox) && resolver_listening(sandbox) => {
            CheckOutcome::Pass
        }
        Backend::Resolved => CheckOutcome::Fail,
    };
    let mut findings = vec![];
    if outcome == CheckOutcome::Fail {
        findings.push(Finding {
            id: CHECK_ID.into(),
            plugin: ID.into(),
            severity: Severity::Medium,
            title_key: "dns-unprotected-title".into(),
            summary_key: "dns-unprotected-summary".into(),
            args: BTreeMap::new(),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: "1970-01-01T00:00:00Z".into(),
        });
    }
    CheckReport {
        results: vec![CheckResult {
            id: CHECK_ID.into(),
            severity: Severity::Medium,
            outcome,
        }],
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn resolved_tree(name: &str) -> (PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-netdns-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("run/systemd/resolve")).unwrap();
        std::fs::create_dir_all(root.join("proc/net")).unwrap();
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nibexwall-dns:x:990:988::/var/lib/ibexwall:/usr/sbin/nologin\n",
        )
        .unwrap();
        symlink(
            "../run/systemd/resolve/stub-resolv.conf",
            root.join("etc/resolv.conf"),
        )
        .unwrap();
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    fn put(root: &std::path::Path, path: &str, content: &str) {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }

    #[test]
    fn plans_the_resolver_settings_dropin_and_unit_changes_in_order() {
        let (_root, sandbox) = resolved_tree("plan");
        let ops = plan(&sandbox, Config::default()).unwrap();
        let kinds: Vec<&str> = ops
            .iter()
            .map(|op| match op {
                Op::FileWrite { path, .. } if path.ends_with("resolver.json") => "settings",
                Op::FileWrite { path, .. } if path == names::ARTIFACT_RESOLVED => "dropin",
                Op::SystemdUnit {
                    unit,
                    action: UnitAction::Enable,
                    ..
                } if unit == SERVICE => "enable-resolver",
                Op::SystemdUnit {
                    unit,
                    action: UnitAction::Restart,
                    ..
                } if unit == RESOLVED => "restart-resolved",
                Op::NftFragment { .. } => "enforce",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "settings",
                "dropin",
                "enable-resolver",
                "restart-resolved",
                "enforce"
            ]
        );
    }

    #[test]
    fn the_planned_settings_are_exactly_what_the_resolver_reads() {
        let (_root, sandbox) = resolved_tree("contract");
        let config = Config::parse(json!({
            "provider": "cloudflare", "transport": "https",
            "lists": [{ "id": "hagezi-pro" }], "allow": ["fine.example"],
        }))
        .unwrap();
        let ops = plan(&sandbox, config).unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!("settings first")
        };
        let settings: Settings = serde_json::from_str(content).unwrap();
        assert_eq!(settings.servers.len(), 2);
        assert!(
            settings
                .servers
                .iter()
                .all(|s| s.transport == Transport::Https)
        );
        assert_eq!(settings.lists[0].id, "hagezi-pro");
        assert!(settings.block_doh);
    }

    #[test]
    fn enforcement_is_last_optional_and_exempts_only_the_resolver_user() {
        let (_root, sandbox) = resolved_tree("enforce");
        let ops = plan(&sandbox, Config::default()).unwrap();
        let Some(Op::NftFragment { fragment }) = ops.last() else {
            panic!("the nft fragment must come last");
        };
        // The core's own typed parser and prefix rule accept it.
        let parsed = ibexwall_sys::ops::parse_fragment(fragment).unwrap();
        assert!(
            parsed
                .chain_names()
                .iter()
                .all(|n| n.starts_with("net_dns_"))
        );
        let rules = &parsed.chains[0].rules;
        assert_eq!(rules[0].verdict, Verdict::Accept);
        assert!(rules[0].oif_loopback);
        assert_eq!(rules[1].uid_not, Some(990));
        assert_eq!(rules[1].dports, vec![53, 853]);
        assert_eq!(rules[1].verdict, Verdict::Reject);

        let off = Config::parse(json!({ "enforcement": false })).unwrap();
        let ops = plan(&sandbox, off).unwrap();
        assert_eq!(ops.len(), 4);
        assert!(!ops.iter().any(|op| matches!(op, Op::NftFragment { .. })));
    }

    #[test]
    fn enforcement_needs_the_resolver_user_to_exist() {
        let (root, sandbox) = resolved_tree("nouser");
        std::fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        let err = plan(&sandbox, Config::default()).unwrap_err();
        assert!(format!("{err:?}").contains("enforcement"), "{err:?}");
        assert!(
            plan(
                &sandbox,
                Config::parse(json!({ "enforcement": false })).unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn uid_lookup_matches_the_whole_user_name() {
        let (root, sandbox) = resolved_tree("uid");
        std::fs::write(
            root.join("etc/passwd"),
            "ibexwall-dns2:x:5:5::/:/bin/false\nibexwall-dns:x:990:988::/:/bin/false\nbad:x:notanumber:1::/:/bin/false\n",
        )
        .unwrap();
        assert_eq!(uid_of(&sandbox, "ibexwall-dns"), Some(990));
        assert_eq!(uid_of(&sandbox, "bad"), None);
        assert_eq!(uid_of(&sandbox, "absent"), None);
    }

    #[test]
    fn the_dropin_points_resolved_at_the_stub_and_never_falls_back_to_plain_dns() {
        let text = dropin_content();
        assert!(text.contains("DNS=127.0.0.153"));
        assert!(text.contains("Domains=~."));
        assert!(text.contains("\nFallbackDNS=\n"));
    }

    #[test]
    fn bad_choices_are_refused_with_the_offending_field() {
        let (_root, sandbox) = resolved_tree("refuse");
        for (config, field) in [
            (json!({ "provider": "nope" }), "provider"),
            (
                json!({ "provider": "cloudflare", "transport": "quic" }),
                "transport",
            ),
            (
                json!({ "lists": [{ "id": "../x", "url": "https://a.example/l" }] }),
                "lists",
            ),
            (
                json!({ "lists": [{ "id": "mine", "url": "http://a.example/l" }] }),
                "lists",
            ),
            (json!({ "surprise": true }), "config"),
        ] {
            let err = Config::parse(config.clone())
                .and_then(|c| plan(&sandbox, c))
                .unwrap_err();
            assert!(format!("{err:?}").contains(field), "{config}: {err:?}");
        }
    }

    #[test]
    fn unsupported_stacks_are_refused_not_guessed() {
        let root = std::env::temp_dir().join(format!("ibx-netdns-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        put(&root, "/etc/resolv.conf", "nameserver 192.0.2.1\n");
        let err = plan(&Sandbox::at(&root), Config::default()).unwrap_err();
        assert!(format!("{err:?}").contains("backend"));
    }

    #[test]
    fn check_fails_until_the_dropin_exists_and_the_resolver_listens() {
        let (root, sandbox) = resolved_tree("check");
        assert_eq!(evaluate(&sandbox).results[0].outcome, CheckOutcome::Fail);
        assert_eq!(evaluate(&sandbox).findings.len(), 1);

        put(&root, names::ARTIFACT_RESOLVED, &dropin_content());
        assert_eq!(evaluate(&sandbox).results[0].outcome, CheckOutcome::Fail);

        let table = format!(
            "  sl  local_address rem_address   st\n   0: {} 00000000:0000 07 0\n",
            listening_hex()
        );
        put(&root, "/proc/net/udp", &table);
        let report = evaluate(&sandbox);
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn check_is_not_assessed_on_an_unsupported_stack() {
        let root = std::env::temp_dir().join(format!("ibx-netdns-na-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        put(&root, "/etc/resolv.conf", "nameserver 192.0.2.1\n");
        let report = evaluate(&Sandbox::at(&root));
        assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn the_listening_address_matches_the_proc_encoding() {
        assert_eq!(listening_hex(), "9900007F:0035");
    }
}
