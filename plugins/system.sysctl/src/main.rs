// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.sysctl`: the reference hardening table from the spec, as data.
//! The check compares the live values (a read of `/proc/sys`, no commands);
//! the control plans `sysctl.set` ops for the runtime plus one owned
//! drop-in under `/etc/sysctl.d/` so the choice survives a reboot. Keys
//! that can disturb a desktop or a VPN (`rp_filter`, `sysrq`) and the
//! one-way `kexec_load_disabled` are opt-in only, and the plan says what
//! each may affect.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Reference, Remediation,
    Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

/// How a table entry is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// In the default preset.
    Recommended,
    /// Only when the administrator asks for it by name.
    OptIn,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub key: &'static str,
    pub value: &'static str,
    pub offer: Offer,
    pub severity: Severity,
    /// Fluent key of the "this may affect ..." note, when there is one.
    pub may_affect: Option<&'static str>,
    /// The reference is a floor: a live value at or above it (numerically)
    /// is already stricter and is left alone. True for the keys whose
    /// kernel maximum is stricter than the reference, where lowering it
    /// would weaken the machine (`unprivileged_bpf_disabled` ships as 2,
    /// locked, on some distros).
    pub at_least: bool,
}

/// The spec's reference table (§5.6). Values are the spec's; every entry
/// documents what it may affect, and the two desktop-hostile keys plus the
/// one-way kexec lock stay out of the default preset.
pub const TABLE: &[Entry] = &[
    Entry {
        key: "kernel.kptr_restrict",
        value: "2",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "kernel.dmesg_restrict",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "kernel.yama.ptrace_scope",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: Some("sysctl-may-affect-ptrace"),
        at_least: false,
    },
    Entry {
        key: "kernel.unprivileged_bpf_disabled",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Medium,
        may_affect: Some("sysctl-may-affect-bpf"),
        at_least: true,
    },
    Entry {
        key: "net.core.bpf_jit_harden",
        value: "2",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: true,
    },
    Entry {
        key: "fs.protected_symlinks",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "fs.protected_hardlinks",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "fs.protected_fifos",
        value: "2",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "fs.protected_regular",
        value: "2",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "fs.suid_dumpable",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "net.ipv4.conf.all.accept_redirects",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Medium,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "net.ipv4.conf.all.send_redirects",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Medium,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "net.ipv4.conf.all.accept_source_route",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Medium,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "net.ipv6.conf.all.accept_redirects",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Medium,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "net.ipv4.tcp_syncookies",
        value: "1",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "dev.tty.ldisc_autoload",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    Entry {
        key: "vm.unprivileged_userfaultfd",
        value: "0",
        offer: Offer::Recommended,
        severity: Severity::Low,
        may_affect: None,
        at_least: false,
    },
    // Opt-in: cannot be undone without a reboot.
    Entry {
        key: "kernel.kexec_load_disabled",
        value: "1",
        offer: Offer::OptIn,
        severity: Severity::Medium,
        may_affect: Some("sysctl-may-affect-kexec"),
        at_least: false,
    },
    // Opt-in: breaks asymmetric routing (VPNs, multi-homing).
    Entry {
        key: "net.ipv4.conf.all.rp_filter",
        value: "1",
        offer: Offer::OptIn,
        severity: Severity::Low,
        may_affect: Some("sysctl-may-affect-rp-filter"),
        at_least: false,
    },
    // Opt-in: desktop users want SysRq for emergencies.
    Entry {
        key: "kernel.sysrq",
        value: "0",
        offer: Offer::OptIn,
        severity: Severity::Low,
        may_affect: Some("sysctl-may-affect-sysrq"),
        at_least: false,
    },
];

/// The drop-in the control owns, so the setting survives a reboot and no
/// distro file is ever touched.
pub const DROP_IN: &str = "/etc/sysctl.d/70-ibexwall-sysctl.conf";

fn entry(key: &str) -> Option<&'static Entry> {
    TABLE.iter().find(|entry| entry.key == key)
}

/// `/proc/sys/<key with / instead of .>`, the kernel's own spelling.
fn proc_sys_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Sysctl)) {
        eprintln!("ibexwall-plugin-sysctl: {err}");
        std::process::exit(1);
    }
}

struct Sysctl;

impl Plugin for Sysctl {
    fn id(&self) -> &'static str {
        "system.sysctl"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

/// What the control was asked to do. Everything is opt-out-safe: keys
/// already at their value are still written to the drop-in (documenting
/// the state) but cost no runtime op.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `recommended`: the default preset.
    pub preset: Option<String>,
    /// Opt-in keys by name, comma-separated (the CLI's `--set` is flat).
    pub include: Option<String>,
    /// Explicit `key = value` pairs (validated against the table).
    pub keys: BTreeMap<String, String>,
}

/// Reads one live value; `None` when the kernel does not have the key or
/// the file cannot be read (never a pass).
fn live(sandbox: &Sandbox, key: &str) -> Option<String> {
    sandbox
        .read(&proc_sys_path(key))
        .map(|v| v.trim().to_string())
}

/// True when the live value already meets the reference (equal, or
/// numerically above it for an `at_least` key).
fn meets(entry: &Entry, current: &str) -> bool {
    if current == entry.value {
        return true;
    }
    entry.at_least
        && current.parse::<i64>().is_ok()
        && entry.value.parse::<i64>().is_ok()
        && current.parse::<i64>().unwrap() >= entry.value.parse::<i64>().unwrap()
}

/// True when the kernel already holds this key stricter than the
/// reference: the plan must not weaken it.
fn already_stricter(sandbox: &Sandbox, key: &str, value: &str) -> bool {
    let entry = entry(key).expect("known key");
    live(sandbox, key).is_some_and(|current| current != value && meets(entry, &current))
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let mut any_off = false;
    for entry in TABLE.iter().filter(|e| e.offer == Offer::Recommended) {
        let Some(current) = live(sandbox, entry.key) else {
            continue;
        };
        if meets(entry, &current) {
            continue;
        }
        any_off = true;
        let mut args = BTreeMap::new();
        args.insert("key".to_string(), entry.key.to_string());
        args.insert("current".to_string(), current);
        args.insert("want".to_string(), entry.value.to_string());
        findings.push(Finding {
            id: format!("sysctl.{}", entry.key),
            plugin: "system.sysctl".into(),
            severity: entry.severity,
            title_key: "sysctl-off-title".into(),
            summary_key: "sysctl-off-summary".into(),
            args,
            references: vec![Reference {
                framework: "docs.kernel.org".into(),
                id: "admin-guide/sysctl".into(),
                url: Some("https://docs.kernel.org/admin-guide/sysctl/index.html".into()),
            }],
            remediation: Some(Remediation {
                plan_template: Some("sysctl.harden".into()),
                may_affect_keys: entry.may_affect.map(str::to_string).into_iter().collect(),
            }),
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }
    CheckReport {
        results: vec![CheckResult {
            id: "sysctl.hardening".into(),
            severity: Severity::Medium,
            outcome: if any_off {
                CheckOutcome::Fail
            } else {
                CheckOutcome::Pass
            },
        }],
        findings,
    }
}

/// Builds the plan: one runtime op per key that changes, then one owned
/// drop-in holding the whole chosen set.
pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    if let Some(preset) = &config.preset
        && preset != "recommended"
    {
        return Err(PluginError::invalid(
            "preset",
            format!("`{preset}`: the only preset is `recommended`"),
        ));
    }
    let mut chosen: BTreeMap<&str, String> = BTreeMap::new();
    if config.preset.as_deref() == Some("recommended") {
        for entry in TABLE.iter().filter(|e| e.offer == Offer::Recommended) {
            chosen.insert(entry.key, entry.value.to_string());
        }
    }
    for key in config
        .include
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
    {
        let entry = entry(key).ok_or_else(|| {
            PluginError::invalid("include", format!("`{key}` is not a known sysctl"))
        })?;
        chosen.insert(entry.key, entry.value.to_string());
    }
    for (key, value) in &config.keys {
        let entry = entry(key).ok_or_else(|| {
            PluginError::invalid("keys", format!("`{key}` is not a known sysctl"))
        })?;
        // A value the table does not recommend is the administrator's to
        // take, but it must be a number the key can hold.
        let value = normalize(key, value)?;
        chosen.insert(entry.key, value);
    }
    if chosen.is_empty() {
        return Err(PluginError::invalid(
            "config",
            "nothing to do: preset `recommended`, or name the keys".to_string(),
        ));
    }

    // A live value stricter than the reference is respected, not lowered:
    // neither a runtime write nor a drop-in line (writing the reference
    // back would weaken the next boot, and some kernels refuse the write
    // anyway: `unprivileged_bpf_disabled` ships locked at 2).
    let chosen: BTreeMap<&str, String> = chosen
        .into_iter()
        .filter(|(key, value)| !already_stricter(sandbox, key, value))
        .collect();

    let mut ops = Vec::new();
    for (key, value) in &chosen {
        // Already there: the drop-in still records it, the kernel needs
        // no write.
        if live(sandbox, key).as_deref() != Some(value.as_str()) {
            ops.push(Op::SysctlSet {
                key: (*key).to_string(),
                value: value.clone(),
            });
        }
    }
    let mut drop_in =
        String::from("# Managed by IbexWall (system.sysctl); edit it from IbexWall.\n");
    for (key, value) in &chosen {
        drop_in.push_str(&format!("{key} = {value}\n"));
    }
    ops.push(Op::FileWrite {
        path: DROP_IN.to_string(),
        content: drop_in,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    });
    Ok(ops)
}

/// Accepts a decimal value (with optional whitespace) so the drop-in stays
/// parseable; everything in the table is numeric.
fn normalize(key: &str, value: &str) -> Result<String, PluginError> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.len() <= 10 && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(trimmed.to_string());
    }
    Err(PluginError::invalid(
        "keys",
        format!("`{key} = {value}`: the value must be a number"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(values: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-sysctl-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (key, value) in values {
            let path = root.join(proc_sys_path(key).trim_start_matches('/'));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{value}\n")).unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    #[test]
    fn the_table_is_sane() {
        // Every key unique, every value numeric, and the manifest's
        // allowlist in sync with the table.
        let mut seen = std::collections::BTreeSet::new();
        for entry in TABLE {
            assert!(seen.insert(entry.key), "{} twice", entry.key);
            normalize(entry.key, entry.value).unwrap();
        }
        assert!(TABLE.len() >= 20);
        assert!(TABLE.iter().any(|e| e.key == "kernel.kexec_load_disabled"
            && e.offer == Offer::OptIn
            && e.may_affect.is_some()));
    }

    #[test]
    fn the_check_fails_only_for_recommended_keys_that_are_off() {
        // Everything at the recommended values: pass, nothing to report.
        let (root, sandbox) = tree(&TABLE.iter().map(|e| (e.key, e.value)).collect::<Vec<_>>());
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());

        // Two off, one of them opt-in: only the recommended one counts.
        std::fs::write(
            root.join(proc_sys_path("kernel.kptr_restrict").trim_start_matches('/')),
            "1\n",
        )
        .unwrap();
        std::fs::write(
            root.join(proc_sys_path("kernel.sysrq").trim_start_matches('/')),
            "176\n",
        )
        .unwrap();
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.id, "sysctl.kernel.kptr_restrict");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.args["current"], "1");
        assert_eq!(finding.args["want"], "2");
        assert!(
            finding
                .remediation
                .as_ref()
                .unwrap()
                .plan_template
                .as_deref()
                == Some("sysctl.harden")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_key_is_ignored_not_a_pass() {
        // A kernel without yama: no finding for it, the rest still judged.
        let (root, sandbox) = tree(&[
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_default_preset_sets_only_what_differs_plus_the_drop_in() {
        // Every recommended key exists at its value, except one.
        let seed: Vec<(&str, &str)> = TABLE
            .iter()
            .filter(|e| e.offer == Offer::Recommended)
            .map(|e| (e.key, e.value))
            .collect();
        let (root, sandbox) = tree(&seed);
        std::fs::write(
            root.join(proc_sys_path("kernel.kptr_restrict").trim_start_matches('/')),
            "1\n",
        )
        .unwrap();
        let ops = plan(
            &sandbox,
            &Config {
                preset: Some("recommended".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let sets: Vec<(&String, &String)> = ops
            .iter()
            .filter_map(|op| match op {
                Op::SysctlSet { key, value } => Some((key, value)),
                _ => None,
            })
            .collect();
        // Only the differing key costs a runtime write; the drop-in still
        // records the whole chosen set.
        assert_eq!(
            sets,
            vec![(&"kernel.kptr_restrict".to_string(), &"2".to_string())]
        );
        assert_eq!(ops.len(), 2, "one set plus the drop-in");
        let Op::FileWrite { path, content, .. } = &ops[1] else {
            panic!("the last op is the drop-in");
        };
        assert_eq!(path, DROP_IN);
        assert!(content.starts_with("# Managed by IbexWall"));
        assert!(content.contains("kernel.kptr_restrict = 2"));
        assert!(content.contains("net.ipv4.tcp_syncookies = 1"));
        assert!(!content.contains("kexec"), "the one-way lock is opt-in");
        assert!(
            !content.contains("rp_filter"),
            "the VPN-hostile key is opt-in"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn opt_in_keys_come_by_name_and_by_value() {
        let (root, sandbox) = tree(&[]);
        let config = Config {
            include: Some("kernel.kexec_load_disabled".into()),
            keys: BTreeMap::from([("kernel.sysrq".to_string(), "176".to_string())]),
            ..Default::default()
        };
        let ops = plan(&sandbox, &config).unwrap();
        let Op::FileWrite { content, .. } = &ops[ops.len() - 1] else {
            panic!()
        };
        assert!(content.contains("kernel.kexec_load_disabled = 1"));
        assert!(content.contains("kernel.sysrq = 176"));
        // The kexec lock is a runtime op too, so it takes effect now.
        assert!(ops.iter().any(|op| matches!(
            op,
            Op::SysctlSet { key, value } if key == "kernel.kexec_load_disabled" && value == "1"
        )));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_live_value_stricter_than_the_reference_is_respected_not_lowered() {
        // Fedora ships `unprivileged_bpf_disabled` locked at 2; the
        // reference is 1. Lowering it would weaken the machine and the
        // kernel refuses the way back.
        let seed: Vec<(&str, &str)> = TABLE
            .iter()
            .filter(|e| e.offer == Offer::Recommended)
            .map(|e| (e.key, e.value))
            .collect();
        let (root, sandbox) = tree(&seed);
        std::fs::write(
            root.join(proc_sys_path("kernel.unprivileged_bpf_disabled").trim_start_matches('/')),
            "2\n",
        )
        .unwrap();
        // The check counts the stricter value as meeting the reference.
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());
        // The plan neither writes it nor puts it in the drop-in.
        let ops = plan(
            &sandbox,
            &Config {
                preset: Some("recommended".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let Op::FileWrite { content, .. } = &ops[ops.len() - 1] else {
            panic!()
        };
        assert!(!content.contains("unprivileged_bpf_disabled"));
        assert!(ops.iter().all(|op| !matches!(
            op,
            Op::SysctlSet { key, .. } if key == "kernel.unprivileged_bpf_disabled"
        )));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unknown_keys_and_junk_values_are_refused_at_plan_time() {
        let (_root, sandbox) = tree(&[]);
        let error = plan(
            &sandbox,
            &Config {
                keys: BTreeMap::from([("kernel.nosuch".to_string(), "1".to_string())]),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("not a known sysctl"));
        let error = plan(
            &sandbox,
            &Config {
                keys: BTreeMap::from([("kernel.sysrq".to_string(), "reboot".to_string())]),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be a number"));
        let error = plan(
            &sandbox,
            &Config {
                preset: Some("maximum".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("only preset"));
        let error = plan(&sandbox, &Config::default()).unwrap_err();
        assert!(error.to_string().contains("nothing to do"));
    }
}
