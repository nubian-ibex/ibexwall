// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.ssh`: the SSH server's settings. The check reads
//! `/etc/ssh/sshd_config` and the files it includes with sshd's own
//! rules for the global scope (the first value of a keyword wins, parsing
//! stops at the first `Match`), so the plugin runs nothing and needs no
//! root. The control writes one owned drop-in named to sort first, then
//! has sshd validate the whole configuration (`sshd -t`) and restarts the
//! service, which keeps existing sessions; if validation fails the engine
//! rolls the file back.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-ibexwall.conf";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Ssh)) {
        eprintln!("ibexwall-plugin-ssh: {err}");
        std::process::exit(1);
    }
}

struct Ssh;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Also turn password sign-in off. Off by default: it locks out anyone
    /// without a key.
    pub password_auth: Option<bool>,
}

impl Plugin for Ssh {
    fn id(&self) -> &'static str {
        "system.ssh"
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

/// The directives of the global scope in the order sshd reads them,
/// following `Include`. Keywords are case-insensitive; the result keeps the
/// first value of each, as sshd does.
pub fn effective(sandbox: &Sandbox) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stopped = false;
    read_file(sandbox, "/etc/ssh/sshd_config", &mut out, &mut stopped, 0)?;
    Some(out)
}

fn read_file(
    sandbox: &Sandbox,
    path: &str,
    out: &mut BTreeMap<String, String>,
    stopped: &mut bool,
    depth: u8,
) -> Option<()> {
    let text = sandbox.read(path)?;
    for line in text.lines() {
        if *stopped {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, value) = line
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .map(|(k, v)| {
                (
                    k.to_ascii_lowercase(),
                    v.trim().trim_matches('"').to_string(),
                )
            })
            .unwrap_or((line.to_ascii_lowercase(), String::new()));
        match keyword.as_str() {
            // Settings after a Match line are conditional: not global.
            "match" => *stopped = true,
            "include" if depth < 4 => {
                for pattern in value.split_whitespace() {
                    for file in expand(sandbox, pattern) {
                        read_file(sandbox, &file, out, stopped, depth + 1);
                    }
                }
            }
            _ => {
                out.entry(keyword).or_insert(value);
            }
        }
    }
    Some(())
}

/// `Include` with a relative path is under `/etc/ssh`; only the forms the
/// distributions ship are supported: a file, or `dir/*.conf` (or `dir/*`).
fn expand(sandbox: &Sandbox, pattern: &str) -> Vec<String> {
    let absolute = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/etc/ssh/{pattern}")
    };
    match absolute.rsplit_once('/') {
        Some((dir, "*.conf")) => sandbox
            .list(dir)
            .into_iter()
            .filter(|name| name.ends_with(".conf"))
            .map(|name| format!("{dir}/{name}"))
            .collect(),
        Some((dir, "*")) => sandbox
            .list(dir)
            .into_iter()
            .map(|name| format!("{dir}/{name}"))
            .collect(),
        _ => vec![absolute],
    }
}

fn value<'a>(settings: &'a BTreeMap<String, String>, key: &str, default: &'a str) -> &'a str {
    settings.get(key).map(String::as_str).unwrap_or(default)
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let Some(settings) = effective(sandbox) else {
        // No sshd_config: no SSH server to judge.
        let outcome = if sandbox.exists("/usr/sbin/sshd") {
            CheckOutcome::NotAssessed
        } else {
            CheckOutcome::NotApplicable
        };
        return CheckReport {
            results: vec![CheckResult {
                id: "ssh.hardening".into(),
                severity: Severity::Medium,
                outcome,
            }],
            findings: vec![],
        };
    };
    let root = value(&settings, "permitrootlogin", "prohibit-password");
    let empty = value(&settings, "permitemptypasswords", "no") == "yes";
    let x11 = value(&settings, "x11forwarding", "no") == "yes";
    let any_scored = root == "yes" || empty || x11;
    let mut findings = Vec::new();
    let mut add =
        |id: &str, severity, args: BTreeMap<String, String>, template: bool, may: &[&str]| {
            findings.push(Finding {
                id: format!("ssh.{id}"),
                plugin: "system.ssh".into(),
                severity,
                title_key: format!("ssh-{id}-title"),
                summary_key: format!("ssh-{id}-summary"),
                args,
                references: vec![],
                remediation: template.then(|| Remediation {
                    plan_template: Some("ssh.harden".into()),
                    may_affect_keys: may.iter().map(|s| s.to_string()).collect(),
                }),
                status: FindingStatus::Open,
                detected_at: detected_at.into(),
            });
        };
    if root == "yes" {
        let mut args = BTreeMap::new();
        args.insert("value".to_string(), root.to_string());
        add("root", Severity::High, args, true, &["ssh-may-affect-root"]);
    }
    if empty {
        add("empty", Severity::High, BTreeMap::new(), true, &[]);
    }
    if x11 {
        add("x11", Severity::Low, BTreeMap::new(), true, &[]);
    }
    // Password sign-in is informational: turning it off needs a key, so the
    // finding offers the plan but does not count against the score.
    if value(&settings, "passwordauthentication", "yes") == "yes" {
        add(
            "password",
            Severity::Info,
            BTreeMap::new(),
            true,
            &["ssh-may-affect-password"],
        );
    }
    CheckReport {
        results: vec![CheckResult {
            id: "ssh.hardening".into(),
            severity: Severity::Medium,
            outcome: if any_scored {
                CheckOutcome::Fail
            } else {
                CheckOutcome::Pass
            },
        }],
        findings,
    }
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let main = sandbox.read("/etc/ssh/sshd_config").ok_or_else(|| {
        PluginError::invalid("config", "there is no /etc/ssh/sshd_config".to_string())
    })?;
    // First value wins, so the drop-in only takes effect when sshd reads
    // the drop-in directory before it reads its own settings.
    let include_before_settings = main
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find(|l| {
            let lower = l.to_ascii_lowercase();
            !lower.starts_with("include")
        })
        .is_none_or(|_| {
            main.lines().map(str::trim).any(|l| {
                l.to_ascii_lowercase().starts_with("include") && l.contains("sshd_config.d")
            }) && {
                let first_directive = main
                    .lines()
                    .map(str::trim)
                    .position(|l| !l.is_empty() && !l.starts_with('#'));
                let include_at = main.lines().map(str::trim).position(|l| {
                    l.to_ascii_lowercase().starts_with("include") && l.contains("sshd_config.d")
                });
                matches!((first_directive, include_at), (Some(a), Some(b)) if b <= a)
            }
        });
    if !include_before_settings {
        return Err(PluginError::invalid(
            "config",
            "sshd_config does not read /etc/ssh/sshd_config.d before its own settings, so a drop-in could not take effect".to_string(),
        ));
    }
    let current = effective(sandbox).unwrap_or_default();
    let mut lines = vec!["# Managed by IbexWall (system.ssh).".to_string()];
    if value(&current, "permitrootlogin", "prohibit-password") == "yes" {
        lines.push("PermitRootLogin prohibit-password".into());
    }
    if value(&current, "permitemptypasswords", "no") == "yes" {
        lines.push("PermitEmptyPasswords no".into());
    }
    if value(&current, "x11forwarding", "no") == "yes" {
        lines.push("X11Forwarding no".into());
    }
    if config.password_auth == Some(false) {
        lines.push("PasswordAuthentication no".into());
    }
    if lines.len() == 1 {
        return Err(PluginError::invalid(
            "config",
            "nothing to change: the settings already meet the reference".to_string(),
        ));
    }
    let unit = if sandbox.exists("/usr/lib/systemd/system/sshd.service")
        || sandbox.exists("/etc/systemd/system/sshd.service")
    {
        "sshd.service"
    } else {
        "ssh.service"
    };
    let mut ops = vec![
        Op::FileWrite {
            path: DROP_IN.into(),
            content: lines.join("\n") + "\n",
            mode: "0600".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        // The whole configuration, checked by sshd itself, before it is
        // restarted: a failure aborts and rolls the file back.
        Op::Exec {
            path: "/usr/sbin/sshd".into(),
            args: vec!["-t".into()],
        },
    ];
    // Restart only a running server (a stopped one stays stopped); a
    // restart keeps the existing sessions.
    if sandbox.exists("/run/sshd.pid") {
        ops.push(Op::SystemdUnit {
            unit: unit.into(),
            action: UnitAction::Restart,
            now: None,
        });
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-ssh-{}-{}",
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

    const INCLUDE_FIRST: &str = "Include /etc/ssh/sshd_config.d/*.conf\n# comment\nX11Forwarding yes\nPermitRootLogin yes\n";

    #[test]
    fn the_first_value_wins_across_includes_and_match_blocks_are_not_global() {
        let (root, sandbox) = tree(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User bob\n  PermitRootLogin no\n  X11Forwarding yes\n",
            ),
            (
                "/etc/ssh/sshd_config.d/10-a.conf",
                "permitrootlogin=prohibit-password\n",
            ),
        ]);
        let settings = effective(&sandbox).unwrap();
        assert_eq!(settings["permitrootlogin"], "prohibit-password");
        assert!(
            !settings.contains_key("x11forwarding"),
            "after Match is conditional"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn findings_follow_the_effective_values_and_defaults() {
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", INCLUDE_FIRST)]);
        let report = evaluate(&sandbox, "now");
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["ssh.root", "ssh.x11", "ssh.password"]);
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].severity, Severity::High);
        std::fs::remove_dir_all(root).unwrap();
        // Defaults only: password sign-in alone is informational.
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", "# nothing set\n")]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "ssh.password");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_server_is_not_applicable_and_an_unreadable_one_is_not_a_pass() {
        let (root, sandbox) = tree(&[]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[("/usr/sbin/sshd", "")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_writes_only_what_differs_validates_and_restarts_a_running_server() {
        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", INCLUDE_FIRST),
            ("/usr/lib/systemd/system/sshd.service", ""),
            ("/run/sshd.pid", "1\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        let Op::FileWrite {
            path,
            content,
            mode,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!(path, DROP_IN);
        assert_eq!(mode, "0600");
        assert!(content.contains("PermitRootLogin prohibit-password"));
        assert!(content.contains("X11Forwarding no"));
        assert!(!content.contains("PasswordAuthentication"), "opt-in only");
        assert!(
            matches!(&ops[1], Op::Exec { path, args } if path == "/usr/sbin/sshd" && args == &["-t"])
        );
        assert!(
            matches!(&ops[2], Op::SystemdUnit { unit, action: UnitAction::Restart, .. } if unit == "sshd.service")
        );
        let ops = plan(
            &sandbox,
            &Config {
                password_auth: Some(false),
            },
        )
        .unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        assert!(content.contains("PasswordAuthentication no"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stopped_server_is_not_started_and_the_debian_unit_name_is_used() {
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", INCLUDE_FIRST)]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert_eq!(ops.len(), 2, "no restart for a server that is not running");
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", INCLUDE_FIRST),
            ("/run/sshd.pid", "1\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert!(matches!(&ops[2], Op::SystemdUnit { unit, .. } if unit == "ssh.service"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_drop_in_that_could_not_take_effect_is_refused() {
        // Settings come before the Include: first value wins, so ours would lose.
        let (root, sandbox) = tree(&[(
            "/etc/ssh/sshd_config",
            "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n",
        )]);
        let error = plan(&sandbox, &Config::default()).unwrap_err();
        assert!(error.to_string().contains("before its own settings"));
        std::fs::remove_dir_all(root).unwrap();
        // Nothing to change.
        let (root, sandbox) = tree(&[(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )]);
        assert!(
            plan(&sandbox, &Config::default())
                .unwrap_err()
                .to_string()
                .contains("nothing to change")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
