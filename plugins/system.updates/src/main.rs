// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.updates`: do security updates install themselves? File-based, no
//! commands: `unattended-upgrades` on Debian and Ubuntu (apt's periodic
//! settings, last file wins), `dnf5-automatic` on Fedora (timer enabled and
//! `apply_updates`). Arch is rolling and has no supported unattended
//! upgrader, so the check is not applicable there. The plugin never
//! installs software: when the tool is missing the finding says so and the
//! plan refuses. Pending-update counts need PackageKit and are not part of
//! this plugin yet.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

const APT_DROP_IN: &str = "/etc/apt/apt.conf.d/52ibexwall-auto-upgrades";
const DNF_DROP_IN: &str = "/etc/dnf/dnf5-plugins/automatic.d/70-ibexwall.conf";
const DNF_TIMER: &str = "dnf5-automatic.timer";
const APT_TIMER: &str = "apt-daily-upgrade.timer";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Updates)) {
        eprintln!("ibexwall-plugin-updates: {err}");
        std::process::exit(1);
    }
}

struct Updates;

impl Plugin for Updates {
    fn id(&self) -> &'static str {
        "system.updates"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, _config: Value) -> Result<Vec<Op>, PluginError> {
        plan(&Sandbox::system())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Apt,
    Dnf,
    Other,
}

fn family(sandbox: &Sandbox) -> Family {
    let text = sandbox
        .read("/etc/os-release")
        .or_else(|| sandbox.read("/usr/lib/os-release"))
        .unwrap_or_default();
    let mut ids = String::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=')
            && (key == "ID" || key == "ID_LIKE")
        {
            ids.push(' ');
            ids.push_str(value.trim_matches('"'));
        }
    }
    let has = |name: &str| ids.split_whitespace().any(|id| id == name);
    if has("debian") || has("ubuntu") {
        Family::Apt
    } else if has("fedora") || has("rhel") {
        Family::Dnf
    } else {
        Family::Other
    }
}

/// The last `Key "value";` of the apt configuration files, in file order.
fn apt_value(sandbox: &Sandbox, key: &str) -> Option<String> {
    let mut found = None;
    for name in sandbox.list("/etc/apt/apt.conf.d") {
        let Some(text) = sandbox.read(&format!("/etc/apt/apt.conf.d/{name}")) else {
            continue;
        };
        for line in text.lines().map(str::trim) {
            if line.starts_with("//") || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix(key) {
                let value = rest.trim().trim_end_matches(';').trim().trim_matches('"');
                found = Some(value.to_string());
            }
        }
    }
    found
}

fn apt_enabled(sandbox: &Sandbox) -> bool {
    apt_value(sandbox, "APT::Periodic::Unattended-Upgrade")
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|days| days >= 1)
}

fn dnf_timer_enabled(sandbox: &Sandbox) -> bool {
    sandbox.exists(&format!(
        "/etc/systemd/system/timers.target.wants/{DNF_TIMER}"
    ))
}

/// `apply_updates = yes` in the main file or any drop-in (later wins).
fn dnf_applies(sandbox: &Sandbox) -> bool {
    let mut applies = false;
    let mut files = vec!["/etc/dnf/dnf5-plugins/automatic.conf".to_string()];
    for name in sandbox.list("/etc/dnf/dnf5-plugins/automatic.d") {
        files.push(format!("/etc/dnf/dnf5-plugins/automatic.d/{name}"));
    }
    for file in files {
        let Some(text) = sandbox.read(&file) else {
            continue;
        };
        for line in text.lines().map(str::trim) {
            if let Some((key, value)) = line.split_once('=')
                && key.trim() == "apply_updates"
            {
                applies = matches!(value.trim(), "yes" | "true" | "1" | "on");
            }
        }
    }
    applies
}

fn tool_installed(sandbox: &Sandbox, family: Family) -> bool {
    match family {
        Family::Apt => sandbox.exists("/usr/bin/unattended-upgrade"),
        Family::Dnf => sandbox.exists(&format!("/usr/lib/systemd/system/{DNF_TIMER}")),
        Family::Other => false,
    }
}

fn tool_name(family: Family) -> &'static str {
    match family {
        Family::Apt => "unattended-upgrades",
        Family::Dnf => "dnf5-plugin-automatic",
        Family::Other => "",
    }
}

/// Whether the package manager still verifies package signatures. Both
/// managers do by default, so the check looks for the explicit escape
/// hatches only; `None` means "cannot tell".
fn signatures_enforced(sandbox: &Sandbox, family: Family) -> Option<bool> {
    let mut text = String::new();
    match family {
        Family::Apt => {
            for name in sandbox.list("/etc/apt/apt.conf.d") {
                if let Some(t) = sandbox.read(&format!("/etc/apt/apt.conf.d/{name}")) {
                    text.push_str(&t);
                    text.push('\n');
                }
            }
        }
        Family::Dnf => {
            if let Some(t) = sandbox.read("/etc/dnf/dnf.conf") {
                text.push_str(&t);
                text.push('\n');
            }
            for name in sandbox.list("/etc/yum.repos.d") {
                if let Some(t) = sandbox.read(&format!("/etc/yum.repos.d/{name}")) {
                    text.push_str(&t);
                    text.push('\n');
                }
            }
        }
        Family::Other => return None,
    }
    let weakened = match family {
        Family::Apt => text.lines().any(|line| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("allowunauthenticated") || lower.contains("allowinsecurerepositories"))
                && (lower.contains("true") || lower.contains("\"1\""))
        }),
        Family::Dnf => text.lines().map(str::trim).any(|line| {
            line.split_once('=')
                .is_some_and(|(k, v)| k.trim() == "gpgcheck" && v.trim() == "0")
        }),
        Family::Other => false,
    };
    Some(!weakened)
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let family = family(sandbox);
    let mut findings = Vec::new();
    let outcome = match family {
        Family::Other => CheckOutcome::NotApplicable,
        _ => {
            let installed = tool_installed(sandbox, family);
            let on = installed
                && match family {
                    Family::Apt => apt_enabled(sandbox),
                    Family::Dnf => dnf_timer_enabled(sandbox) && dnf_applies(sandbox),
                    Family::Other => false,
                };
            if on {
                CheckOutcome::Pass
            } else {
                let (kind, may) = if installed {
                    ("off", vec!["updates-may-affect-reboots".to_string()])
                } else {
                    ("missing", vec![])
                };
                let mut args = BTreeMap::new();
                args.insert("tool".to_string(), tool_name(family).to_string());
                findings.push(Finding {
                    id: "updates.automatic".into(),
                    plugin: "system.updates".into(),
                    severity: Severity::Medium,
                    title_key: format!("updates-auto-{kind}-title"),
                    summary_key: format!("updates-auto-{kind}-summary"),
                    args,
                    references: vec![],
                    remediation: installed.then(|| Remediation {
                        plan_template: Some("updates.automatic".into()),
                        may_affect_keys: may,
                    }),
                    status: FindingStatus::Open,
                    detected_at: detected_at.into(),
                });
                CheckOutcome::Fail
            }
        }
    };
    CheckReport {
        results: vec![
            CheckResult {
                id: "updates.automatic".into(),
                severity: Severity::Medium,
                outcome,
            },
            CheckResult {
                id: "updates.signatures".into(),
                severity: Severity::High,
                outcome: match family {
                    Family::Other => CheckOutcome::NotApplicable,
                    _ => match signatures_enforced(sandbox, family) {
                        Some(true) => CheckOutcome::Pass,
                        Some(false) => {
                            findings.push(Finding {
                                id: "updates.signatures".into(),
                                plugin: "system.updates".into(),
                                severity: Severity::High,
                                title_key: "updates-signatures-title".into(),
                                summary_key: "updates-signatures-summary".into(),
                                args: BTreeMap::new(),
                                references: vec![],
                                remediation: None,
                                status: FindingStatus::Open,
                                detected_at: detected_at.into(),
                            });
                            CheckOutcome::Fail
                        }
                        None => CheckOutcome::NotAssessed,
                    },
                },
            },
        ],
        findings,
    }
}

pub fn plan(sandbox: &Sandbox) -> Result<Vec<Op>, PluginError> {
    let family = family(sandbox);
    if family == Family::Other {
        return Err(PluginError::invalid(
            "config",
            "this distribution has no supported unattended upgrader".to_string(),
        ));
    }
    if !tool_installed(sandbox, family) {
        return Err(PluginError::invalid(
            "config",
            format!(
                "{} is not installed; IbexWall does not install software by itself",
                tool_name(family)
            ),
        ));
    }
    let file = |path: &str, content: &str| Op::FileWrite {
        path: path.into(),
        content: content.into(),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    Ok(match family {
        Family::Apt => vec![
            // Sorts after the package's own 20auto-upgrades, so it wins.
            file(
                APT_DROP_IN,
                "// Managed by IbexWall (system.updates).\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
            ),
            Op::SystemdUnit {
                unit: APT_TIMER.into(),
                action: UnitAction::Enable,
                now: Some(true),
            },
        ],
        Family::Dnf => vec![
            file(
                DNF_DROP_IN,
                "# Managed by IbexWall (system.updates).\n[commands]\napply_updates = yes\n",
            ),
            Op::SystemdUnit {
                unit: DNF_TIMER.into(),
                action: UnitAction::Enable,
                now: Some(true),
            },
        ],
        Family::Other => unreachable!("handled above"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-upd-{}-{}",
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

    fn outcome(report: &CheckReport, id: &str) -> CheckOutcome {
        report.results.iter().find(|r| r.id == id).unwrap().outcome
    }

    const UBUNTU: (&str, &str) = ("/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n");
    const FEDORA: (&str, &str) = ("/etc/os-release", "ID=fedora\n");

    #[test]
    fn a_missing_tool_is_reported_without_a_plan() {
        let (root, sandbox) = tree(&[UBUNTU]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].title_key, "updates-auto-missing-title");
        assert!(report.findings[0].remediation.is_none());
        assert!(
            plan(&sandbox)
                .unwrap_err()
                .to_string()
                .contains("does not install software")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apt_periodic_settings_are_read_in_file_order() {
        let (root, sandbox) = tree(&[
            UBUNTU,
            ("/usr/bin/unattended-upgrade", ""),
            (
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "APT::Periodic::Unattended-Upgrade \"0\";\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            UBUNTU,
            ("/usr/bin/unattended-upgrade", ""),
            (
                "/etc/apt/apt.conf.d/20auto-upgrades",
                "APT::Periodic::Unattended-Upgrade \"0\";\n",
            ),
            (
                "/etc/apt/apt.conf.d/52ibexwall-auto-upgrades",
                "// x\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apt_plan_is_an_owned_file_that_sorts_after_the_packages_and_the_timer() {
        let (root, sandbox) = tree(&[UBUNTU, ("/usr/bin/unattended-upgrade", "")]);
        let ops = plan(&sandbox).unwrap();
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, APT_DROP_IN);
        assert!(path.rsplit('/').next().unwrap() > "50unattended-upgrades");
        assert!(content.contains("Unattended-Upgrade \"1\""));
        assert!(
            matches!(&ops[1], Op::SystemdUnit { unit, action: UnitAction::Enable, .. } if unit == APT_TIMER)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dnf_needs_the_timer_and_apply_updates() {
        let installed = ("/usr/lib/systemd/system/dnf5-automatic.timer", "");
        let (root, sandbox) = tree(&[FEDORA, installed]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        assert_eq!(
            evaluate(&sandbox, "now").findings[0].title_key,
            "updates-auto-off-title"
        );
        std::fs::remove_dir_all(root).unwrap();
        // Timer on but only notifying: still off.
        let (root, sandbox) = tree(&[
            FEDORA,
            installed,
            (
                "/etc/systemd/system/timers.target.wants/dnf5-automatic.timer",
                "",
            ),
            (
                "/etc/dnf/dnf5-plugins/automatic.conf",
                "[commands]\napply_updates = no\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            FEDORA,
            installed,
            (
                "/etc/systemd/system/timers.target.wants/dnf5-automatic.timer",
                "",
            ),
            (
                "/etc/dnf/dnf5-plugins/automatic.conf",
                "[commands]\napply_updates = no\n",
            ),
            (
                "/etc/dnf/dnf5-plugins/automatic.d/70-ibexwall.conf",
                "[commands]\napply_updates = yes\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        let ops = plan(&sandbox).unwrap();
        assert!(matches!(&ops[0], Op::FileWrite { path, .. } if path == DNF_DROP_IN));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rolling_distros_are_not_applicable() {
        let (root, sandbox) = tree(&[("/etc/os-release", "ID=arch\n")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        assert!(plan(&sandbox).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signatures_are_verified_unless_explicitly_weakened() {
        // dnf with gpgcheck off is a failure.
        let (root, sandbox) = tree(&[
            ("/etc/os-release", "ID=fedora\n"),
            ("/etc/dnf/dnf.conf", "gpgcheck=0\n"),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "updates.signatures"),
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();

        // dnf without a weakening directive passes.
        let (root, sandbox) = tree(&[
            ("/etc/os-release", "ID=fedora\n"),
            ("/etc/dnf/dnf.conf", "[main]\ngpgcheck=1\n"),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "updates.signatures"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();

        // apt with AllowUnauthenticated true is a failure.
        let (root, sandbox) = tree(&[
            ("/etc/os-release", "ID=ubuntu\n"),
            (
                "/etc/apt/apt.conf.d/99unsafe",
                "APT::Get::AllowUnauthenticated \"true\";\n",
            ),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "updates.signatures"),
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
