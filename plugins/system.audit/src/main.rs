// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.audit`: shows what Lynis found, when Lynis is installed. IbexWall
//! does not bundle Lynis, does not run it and does not install it: the
//! plugin reads the report Lynis leaves at `/var/log/lynis-report.dat`
//! (`key=value` lines, `warning[]=ID|text|details|solution`). Everything in
//! the report is text from another program and travels as arguments only.
//! Warnings are medium findings and count against the score; suggestions
//! are informational and capped, so a long report cannot flood the screen.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Reference, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

const REPORT: &str = "/var/log/lynis-report.dat";
/// Most suggestions shown; the rest are counted, not listed.
const MAX_SUGGESTIONS: usize = 25;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Audit)) {
        eprintln!("ibexwall-plugin-audit: {err}");
        std::process::exit(1);
    }
}

struct Audit;

impl Plugin for Audit {
    fn id(&self) -> &'static str {
        "system.audit"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// `ID|text|details|solution` with `-` for an empty field, as Lynis writes.
fn parse_entry(value: &str) -> (String, String, String) {
    let mut fields = value.split('|').map(|f| if f == "-" { "" } else { f });
    let id = fields.next().unwrap_or("").to_string();
    let text = fields.next().unwrap_or("").to_string();
    let detail = fields.next().unwrap_or("").to_string();
    (id, text, detail)
}

/// Keeps ids usable as finding ids and Fluent-safe args short.
fn clean(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect()
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let installed = sandbox.exists("/usr/bin/lynis")
        || sandbox.exists("/usr/sbin/lynis")
        || sandbox.exists("/usr/share/lynis");
    let result = |outcome| {
        vec![CheckResult {
            id: "audit.lynis".into(),
            severity: Severity::Medium,
            outcome,
        }]
    };
    let Some(text) = sandbox.read(REPORT) else {
        // Lynis there but no report (or unreadable): never a pass. Not
        // installed: nothing to integrate with.
        let outcome = if installed || sandbox.exists(REPORT) {
            CheckOutcome::NotAssessed
        } else {
            CheckOutcome::NotApplicable
        };
        return CheckReport {
            results: result(outcome),
            findings: vec![],
        };
    };

    let mut index = None;
    let mut tests = String::new();
    let mut warnings = Vec::new();
    let mut suggestions = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "hardening_index" => index = value.trim().parse::<u32>().ok(),
            "tests_executed" => tests = clean(value, 40),
            "warning[]" => warnings.push(parse_entry(value)),
            "suggestion[]" => suggestions.push(parse_entry(value)),
            _ => {}
        }
    }

    let mut findings = Vec::new();
    // Lynis repeats a test id for several entries (one per sysctl, per
    // package...), and finding ids must be unique: later repeats get a
    // counter.
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    let mut finding = |kind: &str, id: &str, text: &str, detail: &str, severity| {
        let base = format!("audit.lynis.{kind}.{}", clean(id, 40));
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        let unique = if *count == 1 {
            base
        } else {
            format!("{base}.{count}")
        };
        let mut args = BTreeMap::new();
        args.insert("test".to_string(), clean(id, 40));
        args.insert("text".to_string(), clean(text, 120));
        args.insert("detail".to_string(), clean(detail, 200));
        Finding {
            id: unique,
            plugin: "system.audit".into(),
            severity,
            title_key: format!("audit-{kind}-title"),
            summary_key: format!("audit-{kind}-summary"),
            args,
            references: vec![Reference {
                framework: "lynis".into(),
                id: clean(id, 40),
                url: None,
            }],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        }
    };
    for (id, text, detail) in &warnings {
        findings.push(finding("warning", id, text, detail, Severity::Medium));
    }
    for (id, text, detail) in suggestions.iter().take(MAX_SUGGESTIONS) {
        findings.push(finding("suggestion", id, text, detail, Severity::Info));
    }
    if let Some(index) = index {
        let mut args = BTreeMap::new();
        args.insert("index".to_string(), index.to_string());
        args.insert("tests".to_string(), tests);
        findings.push(Finding {
            id: "audit.lynis.index".into(),
            plugin: "system.audit".into(),
            severity: Severity::Info,
            title_key: "audit-index-title".into(),
            summary_key: "audit-index-summary".into(),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }
    let outcome = if index.is_none() && warnings.is_empty() && suggestions.is_empty() {
        // A file that is not a Lynis report.
        CheckOutcome::NotAssessed
    } else if warnings.is_empty() {
        CheckOutcome::Pass
    } else {
        CheckOutcome::Fail
    };
    CheckReport {
        results: result(outcome),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-audit-{}-{}",
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

    const REPORT_TEXT: &str = "# Lynis report\nhardening_index=63\ntests_executed=238|\nwarning[]=AUTH-9286|Password file has weak entries|-|-\nwarning[]=SSH-7440|Weak SSH setting|PermitRootLogin|-\nsuggestion[]=KRNL-5820|Disable core dumps|-|-\nsuggestion[]=BOOT-5122|Set a GRUB password|-|-\nirrelevant=value\n";

    #[test]
    fn warnings_fail_and_suggestions_inform() {
        let (root, sandbox) = tree(&[(REPORT, REPORT_TEXT)]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "audit.lynis.warning.AUTH-9286",
                "audit.lynis.warning.SSH-7440",
                "audit.lynis.suggestion.KRNL-5820",
                "audit.lynis.suggestion.BOOT-5122",
                "audit.lynis.index"
            ]
        );
        assert_eq!(report.findings[0].severity, Severity::Medium);
        assert_eq!(report.findings[2].severity, Severity::Info);
        assert_eq!(report.findings[1].args["detail"], "PermitRootLogin");
        assert_eq!(report.findings[4].args["index"], "63");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeated_test_ids_get_unique_finding_ids() {
        let (root, sandbox) = tree(&[(
            REPORT,
            "hardening_index=50\nsuggestion[]=KRNL-6000|a|-|-\nsuggestion[]=KRNL-6000|b|-|-\nsuggestion[]=KRNL-6000|c|-|-\n",
        )]);
        let report = evaluate(&sandbox, "now");
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            &ids[..3],
            [
                "audit.lynis.suggestion.KRNL-6000",
                "audit.lynis.suggestion.KRNL-6000.2",
                "audit.lynis.suggestion.KRNL-6000.3"
            ]
        );
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_report_with_no_warnings_passes() {
        let (root, sandbox) = tree(&[(REPORT, "hardening_index=90\n")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn not_installed_is_not_applicable_and_no_report_is_not_a_pass() {
        let (root, sandbox) = tree(&[]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[("/usr/bin/lynis", "")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[(REPORT, "garbage without structure\n")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn suggestions_are_capped_and_hostile_text_stays_plain() {
        let mut text = String::from("hardening_index=10\n");
        for n in 0..(MAX_SUGGESTIONS + 20) {
            text.push_str(&format!("suggestion[]=T-{n}|Text {n}|-|-\n"));
        }
        text.push_str("warning[]=EVIL-1|<script>alert(1)</script>\u{1b}[31m|a\u{7}b|-\n");
        let (root, sandbox) = tree(&[(REPORT, &text)]);
        let report = evaluate(&sandbox, "now");
        let suggestions = report
            .findings
            .iter()
            .filter(|f| f.id.contains(".suggestion."))
            .count();
        assert_eq!(suggestions, MAX_SUGGESTIONS);
        let evil = report
            .findings
            .iter()
            .find(|f| f.id.ends_with("EVIL-1"))
            .unwrap();
        assert!(!evil.args["text"].contains('\u{1b}'));
        assert!(!evil.args["detail"].contains('\u{7}'));
        // Markup stays in an argument; the keys are fixed.
        assert_eq!(evil.title_key, "audit-warning-title");
        std::fs::remove_dir_all(root).unwrap();
    }
}
