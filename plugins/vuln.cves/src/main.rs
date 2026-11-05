// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `vuln.cves`: the security updates the distribution has published for the
//! packages installed here. Distro sources first, and offline: the package
//! manager answers from its own cache (`dnf5 --cacheonly updateinfo`,
//! `apt-get -s upgrade` against the lists apt already has, `arch-audit`
//! when installed), with a fixed argv, no shell and a time limit. Nothing
//! is downloaded and nothing is sent anywhere, so there is no privacy
//! notice to give: the OSV lookup the spec allows for other ecosystems is
//! not part of this plugin (it would need the network and consent).
//!
//! The parsers take text, so they are tested on real outputs. When the
//! manager cannot answer (no cache), the check says "not assessed".

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

/// Findings listed; the rest are counted in one more.
const MAX_FINDINGS: usize = 50;
const LIMIT: Duration = Duration::from_secs(90);

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Cves)) {
        eprintln!("ibexwall-plugin-cves: {err}");
        std::process::exit(1);
    }
}

struct Cves;

impl Plugin for Cves {
    fn id(&self) -> &'static str {
        "vuln.cves"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        let sandbox = Sandbox::system();
        // The command runs off the async threads: it can take a while.
        tokio::task::spawn_blocking(move || evaluate(&sandbox, &RealRunner, "1970-01-01T00:00:00Z"))
            .await
            .map_err(|e| PluginError::Failed(e.to_string()))
    }
}

/// Runs a fixed argv and returns stdout, or `None` when it cannot run, fails
/// or takes too long.
pub trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
}

struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        let mut child = Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let started = Instant::now();
        loop {
            match child.try_wait().ok()? {
                Some(status) if status.success() => {
                    let mut out = String::new();
                    child.stdout.take()?.read_to_string(&mut out).ok()?;
                    return Some(out);
                }
                Some(_) => return None,
                None if started.elapsed() > LIMIT => {
                    let _ = child.kill();
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

/// One advisory-and-package line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub package: String,
    pub advisory: String,
    pub severity: Severity,
}

fn severity_of(word: &str) -> Severity {
    match word
        .to_ascii_lowercase()
        .trim_end_matches("/sec.")
        .trim_end_matches("/sec")
    {
        "critical" => Severity::Critical,
        "important" | "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

/// `dnf5 updateinfo list --security`: an advisory id, optionally a type and
/// a severity, then the package (name-version-release.arch). Header and
/// blank lines are skipped; anything that does not look like an advisory
/// id is ignored rather than guessed at.
pub fn parse_dnf(text: &str) -> Vec<Update> {
    text.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let advisory = *words.first()?;
            let looks_like_id = advisory.contains('-')
                && advisory.chars().any(|c| c.is_ascii_digit())
                && advisory.chars().next()?.is_ascii_uppercase()
                && advisory
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ':');
            if !looks_like_id || words.len() < 2 {
                return None;
            }
            let severity = words
                .iter()
                .find(|w| {
                    let l = w.to_ascii_lowercase();
                    ["critical", "important", "moderate", "low"]
                        .iter()
                        .any(|s| l.starts_with(s))
                })
                .map(|w| severity_of(w))
                .unwrap_or(Severity::Medium);
            // The package is the last word that is not a date.
            let package = words
                .iter()
                .rev()
                .find(|w| !w.chars().next().is_some_and(|c| c.is_ascii_digit()) || w.contains('.'))
                .filter(|w| **w != advisory)?;
            Some(Update {
                package: package.to_string(),
                advisory: advisory.to_string(),
                severity,
            })
        })
        .collect()
}

/// `apt-get -s upgrade`: `Inst pkg [old] (new Origin:suite [arch])`; an
/// update is security when its origin names a security pocket.
pub fn parse_apt(text: &str) -> Vec<Update> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Inst ")?;
            let package = rest.split_whitespace().next()?;
            let origin = rest.split('(').nth(1)?.to_ascii_lowercase();
            (origin.contains("-security") || origin.contains("security:")).then(|| Update {
                package: package.to_string(),
                advisory: "security pocket".to_string(),
                severity: Severity::Medium,
            })
        })
        .collect()
}

/// `arch-audit`: `Package NAME is affected by CVE-A, CVE-B. High risk!`.
pub fn parse_arch_audit(text: &str) -> Vec<(String, Vec<String>, Severity)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("Package ")?;
            let (package, rest) = rest.split_once(" is affected by ")?;
            let cves: Vec<String> = rest
                .split(|c: char| c == ',' || c == '.' || c.is_whitespace())
                .filter(|w| w.starts_with("CVE-"))
                .map(str::to_string)
                .collect();
            let severity = if rest.contains("Critical") {
                Severity::Critical
            } else if rest.contains("High") {
                Severity::High
            } else if rest.contains("Low") {
                Severity::Low
            } else {
                Severity::Medium
            };
            (!cves.is_empty()).then(|| (package.to_string(), cves, severity))
        })
        .collect()
}

fn family(sandbox: &Sandbox) -> &'static str {
    let text = sandbox
        .read("/etc/os-release")
        .or_else(|| sandbox.read("/usr/lib/os-release"))
        .unwrap_or_default();
    let mut ids = String::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=')
            && (k == "ID" || k == "ID_LIKE")
        {
            ids.push(' ');
            ids.push_str(v.trim_matches('"'));
        }
    }
    let has = |n: &str| ids.split_whitespace().any(|i| i == n);
    if has("debian") || has("ubuntu") {
        "apt"
    } else if has("fedora") || has("rhel") {
        "dnf"
    } else if has("arch") {
        "arch"
    } else {
        "other"
    }
}

pub fn evaluate(sandbox: &Sandbox, runner: &dyn Runner, detected_at: &str) -> CheckReport {
    let id = "cves.security_updates";
    let result = |outcome| {
        vec![CheckResult {
            id: id.into(),
            severity: Severity::High,
            outcome,
        }]
    };
    let empty = |outcome| CheckReport {
        results: result(outcome),
        findings: vec![],
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut make = |kind: &str, key: String, severity, args: BTreeMap<String, String>| {
        findings.push(Finding {
            id: format!("cves.{kind}.{key}"),
            plugin: "vuln.cves".into(),
            severity,
            title_key: format!("cves-{kind}-title"),
            summary_key: format!("cves-{kind}-summary"),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    };
    let arg = |pairs: &[(&str, String)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    };

    let total;
    match family(sandbox) {
        "dnf" => {
            let Some(out) = runner.run(
                "/usr/bin/dnf5",
                &["--cacheonly", "--quiet", "updateinfo", "list", "--security"],
            ) else {
                return empty(CheckOutcome::NotAssessed);
            };
            let updates = parse_dnf(&out);
            total = updates.len();
            for u in updates.iter().take(MAX_FINDINGS) {
                make(
                    "update",
                    format!("{}.{}", u.package, u.advisory),
                    u.severity,
                    arg(&[
                        ("package", u.package.clone()),
                        ("advisory", u.advisory.clone()),
                        ("severity", format!("{:?}", u.severity)),
                    ]),
                );
            }
        }
        "apt" => {
            let Some(out) = runner.run("/usr/bin/apt-get", &["-s", "-q", "upgrade"]) else {
                return empty(CheckOutcome::NotAssessed);
            };
            let updates = parse_apt(&out);
            total = updates.len();
            for u in updates.iter().take(MAX_FINDINGS) {
                make(
                    "update",
                    u.package.clone(),
                    u.severity,
                    arg(&[
                        ("package", u.package.clone()),
                        ("advisory", u.advisory.clone()),
                        ("severity", format!("{:?}", u.severity)),
                    ]),
                );
            }
        }
        "arch" => {
            if !sandbox.exists("/usr/bin/arch-audit") {
                return empty(CheckOutcome::NotApplicable);
            }
            let Some(out) = runner.run("/usr/bin/arch-audit", &[]) else {
                return empty(CheckOutcome::NotAssessed);
            };
            let affected = parse_arch_audit(&out);
            total = affected.len();
            for (package, cves, severity) in affected.iter().take(MAX_FINDINGS) {
                make(
                    "affected",
                    package.clone(),
                    *severity,
                    arg(&[("package", package.clone()), ("cves", cves.join(", "))]),
                );
            }
        }
        _ => return empty(CheckOutcome::NotApplicable),
    }
    if total > MAX_FINDINGS {
        make(
            "more",
            "rest".into(),
            Severity::Info,
            arg(&[("count", (total - MAX_FINDINGS).to_string())]),
        );
    }
    CheckReport {
        results: result(if total == 0 {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        }),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Option<&'static str>);
    impl Runner for Fixed {
        fn run(&self, _: &str, _: &[&str]) -> Option<String> {
            self.0.map(str::to_string)
        }
    }

    fn tree(os: &str, extra: &[&str]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-cve-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/os-release"), os).unwrap();
        for path in extra {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, "").unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    const DNF: &str = "FEDORA-2026-1a2b3c4d5e Important/Sec. openssl-1:3.2.1-1.fc44.x86_64\nFEDORA-2026-ffeedd0011 Moderate/Sec.  curl-8.9.0-2.fc44.x86_64\nFEDORA-2026-99aabbccdd Low/Sec. vim-minimal-2:9.1.0-1.fc44.x86_64\n";
    const APT: &str = "Reading package lists...\nInst libssl3 [3.0.2-1] (3.0.2-2 Ubuntu:24.04/noble-security [amd64])\nInst vim [2:9.0] (2:9.1 Ubuntu:24.04/noble-updates [amd64])\nInst curl [8.5.0-1] (8.5.0-2ubuntu10.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\nConf libssl3 (3.0.2-2 Ubuntu:24.04/noble-security [amd64])\n";

    #[test]
    fn dnf_advisories_become_findings_with_their_severity() {
        let updates = parse_dnf(DNF);
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].package, "openssl-1:3.2.1-1.fc44.x86_64");
        assert_eq!(updates[0].severity, Severity::High);
        assert_eq!(updates[1].severity, Severity::Medium);
        assert_eq!(updates[2].severity, Severity::Low);
        let (root, sandbox) = tree("ID=fedora\n", &[]);
        let report = evaluate(&sandbox, &Fixed(Some(DNF)), "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings.len(), 3);
        assert_eq!(
            report.findings[0].args["advisory"],
            "FEDORA-2026-1a2b3c4d5e"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dnf_headers_blank_lines_and_noise_are_not_advisories() {
        let text = "Name Type Severity Package Issued\n\nLast metadata expiration check: 1 day ago.\nsome random text here\n";
        assert!(parse_dnf(text).is_empty());
        let (root, sandbox) = tree("ID=fedora\n", &[]);
        assert_eq!(
            evaluate(&sandbox, &Fixed(Some(text)), "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apt_counts_only_updates_from_a_security_pocket() {
        let updates = parse_apt(APT);
        let names: Vec<&str> = updates.iter().map(|u| u.package.as_str()).collect();
        assert_eq!(names, ["libssl3", "curl"]);
    }

    #[test]
    fn arch_audit_lines_name_the_cves() {
        let text = "Package openssl is affected by CVE-2026-0001, CVE-2026-0002. High risk!\nPackage zlib is affected by CVE-2026-9. Low risk!\nsomething else\n";
        let affected = parse_arch_audit(text);
        assert_eq!(affected.len(), 2);
        assert_eq!(affected[0].1, ["CVE-2026-0001", "CVE-2026-0002"]);
        assert_eq!(affected[0].2, Severity::High);
        assert_eq!(affected[1].2, Severity::Low);
        let (root, sandbox) = tree("ID=arch\n", &["/usr/bin/arch-audit"]);
        assert_eq!(
            evaluate(&sandbox, &Fixed(Some(text)), "now").findings.len(),
            2
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree("ID=arch\n", &[]);
        assert_eq!(
            evaluate(&sandbox, &Fixed(None), "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_manager_that_cannot_answer_is_not_a_pass() {
        let (root, sandbox) = tree("ID=ubuntu\nID_LIKE=debian\n", &[]);
        let report = evaluate(&sandbox, &Fixed(None), "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
        assert!(report.findings.is_empty());
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree("ID=nixos\n", &[]);
        assert_eq!(
            evaluate(&sandbox, &Fixed(Some("x")), "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_long_list_is_capped_and_the_rest_counted() {
        let mut text = String::new();
        for n in 0..(MAX_FINDINGS + 7) {
            text.push_str(&format!(
                "FEDORA-2026-{n:010} Important/Sec. pkg{n}-1.0-1.fc44.x86_64\n"
            ));
        }
        let (root, sandbox) = tree("ID=fedora\n", &[]);
        let report = evaluate(
            &sandbox,
            &Fixed(Some(Box::leak(text.into_boxed_str()))),
            "now",
        );
        assert_eq!(report.findings.len(), MAX_FINDINGS + 1);
        let more = report.findings.last().unwrap();
        assert_eq!(more.args["count"], "7");
        std::fs::remove_dir_all(root).unwrap();
    }
}
