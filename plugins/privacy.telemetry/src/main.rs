// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `privacy.telemetry`: usage reporting that the distribution and some apps
//! send. Check only, and honest about it: each finding names what is on and
//! leaves the decision to the user. The control the spec lists is not
//! offered here: the only browser policy the core may write is the DNS one
//! (ADR-0034's allowlist), and the distro-owned settings behind these
//! findings (`/etc/default/*`, repository files) are not IbexWall's to
//! edit. Findings are informational and never count against the score.
//!
//! Covered: popularity-contest (Debian, Ubuntu), apport and motd-news
//! (Ubuntu), `countme` in package repositories (Fedora), and Firefox
//! without a system policy that turns its telemetry off.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Telemetry)) {
        eprintln!("ibexwall-plugin-telemetry: {err}");
        std::process::exit(1);
    }
}

struct Telemetry;

impl Plugin for Telemetry {
    fn id(&self) -> &'static str {
        "privacy.telemetry"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// `KEY="value"` or `KEY=value`, last assignment, comments skipped.
fn shell_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches(['"', '\'']).to_string())
        .next_back()
}

fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "yes" | "true" | "1" | "on"
    )
}

/// A repository section with `countme=1` that is not disabled.
fn countme_repo(sandbox: &Sandbox) -> bool {
    sandbox
        .list("/etc/yum.repos.d")
        .iter()
        .filter(|f| f.ends_with(".repo"))
        .filter_map(|f| sandbox.read(&format!("/etc/yum.repos.d/{f}")))
        .any(|text| {
            let (mut enabled, mut countme, mut hit) = (true, false, false);
            for line in text.lines().map(str::trim) {
                if line.starts_with('[') {
                    hit |= enabled && countme;
                    (enabled, countme) = (true, false);
                } else if let Some(v) = line.strip_prefix("enabled=") {
                    enabled = v.trim() != "0";
                } else if let Some(v) = line.strip_prefix("countme=") {
                    countme = v.trim() == "1";
                }
            }
            hit || (enabled && countme)
        })
}

fn firefox_telemetry_off(sandbox: &Sandbox) -> bool {
    [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
    ]
    .iter()
    .filter_map(|p| sandbox.read(p))
    .filter_map(|t| serde_json::from_str::<Value>(&t).ok())
    .any(|v| v["policies"]["DisableTelemetry"] == Value::Bool(true))
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut on: Vec<&str> = Vec::new();
    if sandbox.exists("/usr/sbin/popularity-contest")
        && sandbox
            .read("/etc/popularity-contest.conf")
            .and_then(|t| shell_value(&t, "PARTICIPATE"))
            .is_some_and(|v| truthy(&v))
    {
        on.push("popcon");
    }
    if (sandbox.exists("/usr/share/apport") || sandbox.exists("/usr/bin/apport-cli"))
        && sandbox
            .read("/etc/default/apport")
            .and_then(|t| shell_value(&t, "enabled"))
            .is_some_and(|v| v == "1")
    {
        on.push("apport");
    }
    let motd_installed = sandbox.exists("/usr/lib/ubuntu-release-upgrader/release-upgrade-motd")
        || sandbox.exists("/etc/update-motd.d/50-motd-news");
    if motd_installed
        && sandbox
            .read("/etc/default/motd-news")
            .and_then(|t| shell_value(&t, "ENABLED"))
            .is_some_and(|v| v == "1")
    {
        on.push("motd");
    }
    if countme_repo(sandbox) {
        on.push("countme");
    }
    let firefox = sandbox.exists("/usr/bin/firefox")
        || sandbox.exists("/usr/lib/firefox")
        || sandbox.exists("/usr/lib64/firefox");
    if firefox && !firefox_telemetry_off(sandbox) {
        on.push("firefox");
    }
    let findings: Vec<Finding> = on
        .iter()
        .map(|kind| Finding {
            id: format!("telemetry.{kind}"),
            plugin: "privacy.telemetry".into(),
            severity: Severity::Info,
            title_key: format!("telemetry-{kind}-title"),
            summary_key: format!("telemetry-{kind}-summary"),
            args: BTreeMap::new(),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        })
        .collect();
    // Informational: knowing is the point, so the check itself passes.
    let outcome = if sandbox.exists("/etc") {
        CheckOutcome::Pass
    } else {
        CheckOutcome::NotAssessed
    };
    CheckReport {
        results: vec![CheckResult {
            id: "telemetry.reporting".into(),
            severity: Severity::Info,
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
            "ibx-tel-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    fn ids(sandbox: &Sandbox) -> Vec<String> {
        evaluate(sandbox, "now")
            .findings
            .iter()
            .map(|f| f.id.clone())
            .collect()
    }

    #[test]
    fn ubuntu_reporting_that_is_on_is_listed() {
        let (root, sandbox) = tree(&[
            ("/usr/sbin/popularity-contest", ""),
            ("/etc/popularity-contest.conf", "# x\nPARTICIPATE=\"yes\"\n"),
            ("/usr/share/apport/apport", ""),
            (
                "/etc/default/apport",
                "# set this to 0 to disable apport\nenabled=1\n",
            ),
            ("/etc/update-motd.d/50-motd-news", ""),
            ("/etc/default/motd-news", "ENABLED=1\n"),
        ]);
        assert_eq!(
            ids(&sandbox),
            ["telemetry.popcon", "telemetry.apport", "telemetry.motd"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn turned_off_or_not_installed_is_not_listed() {
        let (root, sandbox) = tree(&[
            ("/usr/sbin/popularity-contest", ""),
            ("/etc/popularity-contest.conf", "PARTICIPATE=\"no\"\n"),
            ("/usr/share/apport/apport", ""),
            ("/etc/default/apport", "enabled=0\n"),
            // Settings for software that is not installed mean nothing.
            ("/etc/default/motd-news", "ENABLED=1\n"),
        ]);
        assert!(ids(&sandbox).is_empty());
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fedora_countme_counts_only_for_enabled_repositories() {
        let (root, sandbox) = tree(&[(
            "/etc/yum.repos.d/fedora.repo",
            "[fedora]\nenabled=1\ncountme=1\n[fedora-debuginfo]\nenabled=0\n",
        )]);
        assert_eq!(ids(&sandbox), ["telemetry.countme"]);
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[("/etc/yum.repos.d/off.repo", "[x]\nenabled=0\ncountme=1\n")]);
        assert!(ids(&sandbox).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn firefox_is_listed_until_a_system_policy_turns_its_telemetry_off() {
        let (root, sandbox) = tree(&[("/usr/bin/firefox", "")]);
        assert_eq!(ids(&sandbox), ["telemetry.firefox"]);
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            ("/usr/bin/firefox", ""),
            (
                "/etc/firefox/policies/policies.json",
                "{\"policies\":{\"DisableTelemetry\":true}}",
            ),
        ]);
        assert!(ids(&sandbox).is_empty());
        std::fs::remove_dir_all(root).unwrap();
        // A DNS-only policy file does not turn telemetry off.
        let (root, sandbox) = tree(&[
            ("/usr/bin/firefox", ""),
            (
                "/etc/firefox/policies/policies.json",
                "{\"policies\":{\"DNSOverHTTPS\":{\"Enabled\":false}}}",
            ),
        ]);
        assert_eq!(ids(&sandbox), ["telemetry.firefox"]);
        std::fs::remove_dir_all(root).unwrap();
    }
}
