// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.coredump`: are crash dumps kept on disk? A dump holds the
//! program's memory, passwords and keys included. The check reads
//! systemd-coredump's configuration the way systemd does (later files and
//! drop-ins win, `/etc` over `/usr/lib`); the control writes one owned
//! drop-in with `Storage=none` and `ProcessSizeMax=0`. systemd-coredump
//! reads its configuration at every crash, so nothing is restarted.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

const DROP_IN: &str = "/etc/systemd/coredump.conf.d/70-ibexwall.conf";
const CONTENT: &str =
    "# Managed by IbexWall (system.coredump).\n[Coredump]\nStorage=none\nProcessSizeMax=0\n";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Coredump)) {
        eprintln!("ibexwall-plugin-coredump: {err}");
        std::process::exit(1);
    }
}

struct Coredump;

impl Plugin for Coredump {
    fn id(&self) -> &'static str {
        "system.coredump"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, _config: Value) -> Result<Vec<Op>, PluginError> {
        Ok(plan())
    }
}

pub fn plan() -> Vec<Op> {
    vec![Op::FileWrite {
        path: DROP_IN.into(),
        content: CONTENT.into(),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }]
}

/// The `[Coredump]` settings systemd would use: each directory level is a
/// layer (`/usr/lib` below `/etc`), a drop-in of the same name replaces the
/// lower one, and drop-ins apply in file-name order after the main file.
fn settings(sandbox: &Sandbox) -> BTreeMap<String, String> {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut main = String::new();
    for base in ["/usr/lib/systemd", "/etc/systemd"] {
        if let Some(text) = sandbox.read(&format!("{base}/coredump.conf")) {
            main = text;
        }
        for name in sandbox.list(&format!("{base}/coredump.conf.d")) {
            if name.ends_with(".conf")
                && let Some(text) = sandbox.read(&format!("{base}/coredump.conf.d/{name}"))
            {
                files.insert(name, text);
            }
        }
    }
    let mut out = BTreeMap::new();
    for text in std::iter::once(main).chain(files.into_values()) {
        let mut in_section = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                in_section = name == "Coredump";
            } else if in_section && let Some((key, value)) = line.split_once('=') {
                out.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    out
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let pattern = sandbox
        .read("/proc/sys/kernel/core_pattern")
        .unwrap_or_default();
    // Without systemd-coredump the kernel writes files itself (or discards
    // them): a different feature, not this plugin's to judge.
    let piped = pattern.contains("systemd-coredump");
    let mut findings = Vec::new();
    let outcome = if sandbox.read("/proc/sys/kernel/core_pattern").is_none() {
        CheckOutcome::NotAssessed
    } else if !piped {
        CheckOutcome::NotApplicable
    } else {
        let settings = settings(sandbox);
        let storage = settings
            .get("Storage")
            .map(String::as_str)
            .unwrap_or("external");
        let size_zero = settings.get("ProcessSizeMax").is_some_and(|v| v == "0");
        if storage == "none" || size_zero {
            CheckOutcome::Pass
        } else {
            let mut args = BTreeMap::new();
            args.insert("storage".to_string(), storage.to_string());
            findings.push(Finding {
                id: "coredump.stored".into(),
                plugin: "system.coredump".into(),
                severity: Severity::Low,
                title_key: "coredump-stored-title".into(),
                summary_key: "coredump-stored-summary".into(),
                args,
                references: vec![],
                remediation: Some(Remediation {
                    plan_template: Some("coredump.disable".into()),
                    may_affect_keys: vec!["coredump-may-affect-debugging".into()],
                }),
                status: FindingStatus::Open,
                detected_at: detected_at.into(),
            });
            CheckOutcome::Fail
        }
    };
    CheckReport {
        results: vec![CheckResult {
            id: "coredump.storage".into(),
            severity: Severity::Low,
            outcome,
        }],
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-core-{}-{}",
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

    const PIPED: (&str, &str) = (
        "/proc/sys/kernel/core_pattern",
        "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
    );

    #[test]
    fn stored_by_default_is_a_finding() {
        let (root, sandbox) = tree(&[PIPED]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].args["storage"], "external");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_none_passes_wherever_it_is_set() {
        for (path, content) in [
            ("/etc/systemd/coredump.conf", "[Coredump]\nStorage=none\n"),
            (
                "/usr/lib/systemd/coredump.conf.d/10-x.conf",
                "[Coredump]\nStorage=none\n",
            ),
            ("/etc/systemd/coredump.conf.d/70-ibexwall.conf", CONTENT),
        ] {
            let (root, sandbox) = tree(&[PIPED, (path, content)]);
            assert_eq!(
                evaluate(&sandbox, "now").results[0].outcome,
                CheckOutcome::Pass,
                "{path}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn a_later_drop_in_wins_and_comments_and_other_sections_are_ignored() {
        let (root, sandbox) = tree(&[
            PIPED,
            (
                "/etc/systemd/coredump.conf.d/10-a.conf",
                "[Coredump]\nStorage=none\n",
            ),
            (
                "/etc/systemd/coredump.conf.d/20-b.conf",
                "# Storage=none\n[Coredump]\nStorage=journal\n[Other]\nStorage=none\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].args["storage"], "journal");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_systemd_coredump_it_is_not_this_checks_business() {
        let (root, sandbox) = tree(&[("/proc/sys/kernel/core_pattern", "core\n")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        let (root2, sandbox2) = tree(&[]);
        assert_eq!(
            evaluate(&sandbox2, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(root2).unwrap();
    }

    #[test]
    fn the_plan_is_one_owned_drop_in() {
        let ops = plan();
        assert_eq!(ops.len(), 1);
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, DROP_IN);
        assert!(content.contains("Storage=none") && content.contains("ProcessSizeMax=0"));
    }
}
