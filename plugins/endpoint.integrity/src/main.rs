// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `endpoint.integrity`: the package manager's own word on which installed
//! files are not what it shipped (`rpm -Va`, `dpkg --verify`, `pacman -Qkk`;
//! AIDE too when it is set up). Configuration files and documentation are
//! meant to change, so only program files under system directories are
//! reported; a changed binary or library is high severity, because that is
//! how malware stays in place. Fixed argv, no shell, a time limit, and
//! nothing is downloaded. When the tool cannot answer, the check says "not
//! assessed" instead of guessing.
//!
//! The verifier runs as a child of the daemon, inside its hardened unit, so
//! some of the filesystem is not what the package manager expects there:
//! `ProtectHome` empties /home and /root, `ProtectKernelModules` masks
//! /usr/lib/modules, `PrivateTmp` gives /tmp a life of its own. Paths under
//! those are not reported (they would be noise), and neither are mode-only
//! or time-only differences: only a changed digest or size, a changed link
//! or a missing file counts. Full-fidelity verification needs a unit of the
//! plugin's own (F10).

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

/// AIDE on a laptop; the package verifier gets longer, its first run is
/// I/O bound over every installed file.
const LIMIT: Duration = Duration::from_secs(120);
const VERIFY_LIMIT: Duration = Duration::from_secs(300);
/// Findings listed; the rest are counted in one more.
const MAX_FINDINGS: usize = 20;
/// Only these count: program files, data and services, not configuration
/// (which is meant to change) or documentation.
const SYSTEM_PREFIXES: [&str; 7] = [
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/usr",
];

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Integrity)) {
        eprintln!("ibexwall-plugin-integrity: {err}");
        std::process::exit(1);
    }
}

struct Integrity;

/// Runs a fixed argv; a non-zero exit is still an answer (verifiers use it
/// to mean "differences found"), so only a failure to run or a timeout
/// returns `None`.
pub trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
    /// The package verifier: slower (see `VERIFY_LIMIT`).
    fn run_verify(&self, program: &str, args: &[&str]) -> Option<String> {
        self.run(program, args)
    }
}

pub struct RealRunner;

impl RealRunner {
    fn run_within(&self, program: &str, args: &[&str], limit: Duration) -> Option<String> {
        let started = Instant::now();
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // pacman reports what it finds on stderr; the others use stdout.
            // What the tools say beyond that is read like the rest and,
            // being unparseable, ignored.
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        // Read while waiting, or a chatty verifier fills the pipe and both
        // sides wait forever.
        let mut stdout = child.stdout.take()?;
        let mut stderr = child.stderr.take()?;
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout.read_to_string(&mut text);
            text
        });
        let err_reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        let deadline = started + limit;
        while child.try_wait().ok().flatten().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let mut text = reader.join().ok()?;
        text.push('\n');
        text.push_str(&err_reader.join().ok()?);
        Some(text)
    }
}

impl Runner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        self.run_within(program, args, LIMIT)
    }

    fn run_verify(&self, program: &str, args: &[&str]) -> Option<String> {
        self.run_within(program, args, VERIFY_LIMIT)
    }
}

/// The package manager that verifies on this machine, or `None`.
pub fn family(sandbox: &Sandbox) -> Option<(&'static str, &'static str, Vec<&'static str>)> {
    if sandbox.exists("/usr/bin/rpm") {
        return Some(("rpm", "/usr/bin/rpm", vec!["-Va"]));
    }
    if sandbox.exists("/usr/bin/dpkg") {
        return Some(("dpkg", "/usr/bin/dpkg", vec!["--verify"]));
    }
    if sandbox.exists("/usr/bin/pacman") {
        return Some(("pacman", "/usr/bin/pacman", vec!["-Qkk"]));
    }
    None
}

fn is_system_file(path: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p))
        && !MASKED_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Paths the daemon's own unit hides or replaces: reporting them would say
/// the package manager is unhappy about IbexWall's sandbox.
const MASKED_PREFIXES: [&str; 7] = [
    "/usr/lib/modules",
    "/lib/modules",
    "/home/",
    "/root",
    "/tmp/",
    "/var/tmp/",
    "/run/user",
];

/// `rpm -Va`: `S.5....T.  c /etc/...`. The flags, a type letter (c config,
/// d doc, g ghost, l license, r readme), then the path.
pub fn parse_rpm(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let flags = line.get(0..9)?;
            let rest = &line[9..];
            let mut chars = rest.chars();
            let kind = chars.next()?;
            let path = chars.as_str().trim();
            // Only strong signals: a changed digest (5) or size (S), a
            // changed link (L), or a file that is gone. Mode, owner and
            // time alone are routine (and noisy under the daemon's unit).
            let missing = flags.starts_with("missing");
            let strong = flags.contains('5') || flags.contains('S') || flags.contains('L');
            if (!missing && !strong) || path.is_empty() {
                return None;
            }
            if matches!(kind, 'c' | 'd' | 'g' | 'l' | 'r') || !is_system_file(path) {
                return None;
            }
            Some(path.to_string())
        })
        .collect()
}

/// `dpkg --verify`: `??5??????c /etc/...` (a trailing `c` is a conffile).
pub fn parse_dpkg(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let path = line.split_whitespace().last()?;
            // dpkg's line is the changed checks then the path; a `5` is a
            // changed digest. A trailing `c` marks a conffile.
            if path.starts_with("??") || path.len() < 2 || !line.contains('5') {
                return None;
            }
            if line.contains(&format!("c {path}")) || !is_system_file(path) {
                return None;
            }
            Some(path.to_string())
        })
        .collect()
}

/// `pacman -Qkk`: `warning: pkg: /path (size mismatch)` and summaries.
pub fn parse_pacman(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim().strip_prefix("warning:")?.trim();
            // "pkg: /path (reason)" or "pkg: /path (Metadata ... failed)".
            let (_, rest) = line.split_once(": ")?;
            let path = rest.split_whitespace().next()?;
            let reason = rest.split_once('(').map(|(_, r)| r).unwrap_or("");
            // Time and metadata mismatches are routine; content and size are
            // not, and a file pacman cannot read is not a change here.
            let weak = reason.contains("time") || reason.contains("Metadata");
            if weak || !path.starts_with('/') || !is_system_file(path) {
                return None;
            }
            Some(path.to_string())
        })
        .collect()
}

impl Plugin for Integrity {
    fn id(&self) -> &'static str {
        "endpoint.integrity"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        let sandbox = Sandbox::system();
        let sandbox = std::sync::Arc::new(sandbox);
        let s = Arc::clone(&sandbox);
        tokio::task::spawn_blocking(move || evaluate(&s, &RealRunner, "1970-01-01T00:00:00Z"))
            .await
            .map_err(|e| PluginError::Failed(e.to_string()))
    }
}

use std::sync::Arc;

fn evaluate(sandbox: &Sandbox, runner: &dyn Runner, detected_at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let mut results = Vec::new();

    // AIDE, when someone set it up: its own word, or nothing claimed.
    let aide = if sandbox.exists("/usr/bin/aide") && sandbox.exists("/var/lib/aide/aide.db") {
        match runner.run("/usr/bin/aide", &["--check"]) {
            Some(output) if output.contains("All files match AIDE database") => {
                Some(CheckOutcome::Pass)
            }
            Some(output) => {
                let count = output
                    .lines()
                    .filter(|l| {
                        l.starts_with("added:")
                            || l.starts_with("changed:")
                            || l.starts_with("removed:")
                    })
                    .count();
                findings.push(Finding {
                    id: "integrity.aide".into(),
                    plugin: "endpoint.integrity".into(),
                    severity: Severity::High,
                    title_key: "integrity-added-title".into(),
                    summary_key: "integrity-added-summary".into(),
                    args: BTreeMap::from([("count".to_string(), count.to_string())]),
                    references: vec![],
                    remediation: None,
                    status: FindingStatus::Open,
                    detected_at: detected_at.into(),
                });
                Some(CheckOutcome::Fail)
            }
            None => Some(CheckOutcome::NotAssessed),
        }
    } else {
        None // not set up on this machine: not this check's to claim
    };
    if let Some(outcome) = aide {
        results.push(CheckResult {
            id: "integrity.aide".into(),
            severity: Severity::High,
            outcome,
        });
    }

    let packages = match family(sandbox) {
        None => None,
        Some((_name, program, args)) => {
            let argv: Vec<&str> = args.to_vec();
            runner.run_verify(program, &argv)
        }
    };
    let altered: Vec<String> = match (&packages, family(sandbox).map(|f| f.0)) {
        (Some(text), Some("rpm")) => parse_rpm(text),
        (Some(text), Some("dpkg")) => parse_dpkg(text),
        (Some(text), Some("pacman")) => parse_pacman(text),
        _ => vec![],
    };
    let outcome = match packages {
        None => CheckOutcome::NotAssessed,
        Some(_) if altered.is_empty() => CheckOutcome::Pass,
        Some(_) => CheckOutcome::Fail,
    };
    let mut overflow = 0usize;
    for path in &altered {
        if findings.len() >= MAX_FINDINGS {
            overflow += 1;
            continue;
        }
        findings.push(Finding {
            id: "integrity.altered".into(),
            plugin: "endpoint.integrity".into(),
            severity: Severity::High,
            title_key: "integrity-altered-title".into(),
            summary_key: "integrity-altered-summary".into(),
            args: BTreeMap::from([("path".to_string(), path.clone())]),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }
    if overflow > 0 {
        findings.push(Finding {
            id: "integrity.more".into(),
            plugin: "endpoint.integrity".into(),
            severity: Severity::High,
            title_key: "integrity-more-title".into(),
            summary_key: "integrity-more-summary".into(),
            args: BTreeMap::from([("count".to_string(), overflow.to_string())]),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }
    results.push(CheckResult {
        id: "integrity.packages".into(),
        severity: Severity::High,
        outcome,
    });
    CheckReport { results, findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tree(files: &[(&str, &str)]) -> (PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-int-{}-{}",
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

    #[derive(Default)]
    struct Fake(Vec<(String, String)>);

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            let key = format!("{program} {}", args.join(" "));
            self.0
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
        }
    }

    #[test]
    fn rpm_reports_program_files_and_skips_config_docs_mode_and_masked() {
        let text = "\
S.5....T.  c /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
S.5....T.  d /usr/share/man/man1/ls.1.gz
.......T.    /usr/bin/ls\n\
missing    d /usr/share/doc/coreutils/README\n\
S.5....T.    /usr/bin/hostid\n\
.M.......    /usr/lib/systemd/system/sshd.service\n\
.M.......    /home\n\
S.5....T.    /usr/lib/modules/6.19/vmlinuz\n";
        // Config, docs, time-only, mode-only and masked paths stay out.
        assert_eq!(parse_rpm(text), ["/usr/bin/hostid"]);
    }

    #[test]
    fn dpkg_reports_program_files_and_skips_conffiles() {
        let text = "\
??5??????c /etc/apt/apt.conf.d/01autoremove\n\
??5?????? /usr/bin/hostid\n\
??5?????? /etc/hosts\n";
        assert_eq!(parse_dpkg(text), ["/usr/bin/hostid"]);
    }

    #[test]
    fn pacman_reports_the_file_lines_not_the_summaries() {
        let text = "\
warning: coreutils: /usr/bin/hostid (size mismatch)\n\
coreutils: 2381 total files, 1 altered file\n\
warning: bash: /etc/skel/.bashrc (modification time mismatch)";
        assert_eq!(parse_pacman(text), ["/usr/bin/hostid"]);
    }

    #[test]
    fn an_altered_binary_is_a_finding_and_a_clean_run_passes() {
        let (root, sandbox) = tree(&[("/usr/bin/rpm", "")]);
        let dirty = Fake(vec![(
            "/usr/bin/rpm -Va".into(),
            "S.5....T.    /usr/bin/hostid\n".into(),
        )]);
        let report = evaluate(&sandbox, &dirty, "now");
        assert_eq!(report.results.last().unwrap().outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].args["path"], "/usr/bin/hostid");
        assert_eq!(report.findings[0].severity, Severity::High);

        let clean = Fake(vec![(
            "/usr/bin/rpm -Va".into(),
            "S.5....T.  c /etc/x\n".into(),
        )]);
        let report = evaluate(&sandbox, &clean, "now");
        assert_eq!(report.results.last().unwrap().outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_a_manager_nothing_is_claimed_and_a_flood_is_counted() {
        let (root, sandbox) = tree(&[]);
        let report = evaluate(&sandbox, &Fake::default(), "now");
        assert_eq!(
            report.results.last().unwrap().outcome,
            CheckOutcome::NotAssessed
        );
        assert!(report.findings.is_empty());

        let (rpm_root, rpm_sandbox) = tree(&[("/usr/bin/rpm", "")]);
        let flood: String = (0..30)
            .map(|n| format!("S.5....T.    /usr/bin/tool{n}\n"))
            .collect();
        let flood = Fake(vec![("/usr/bin/rpm -Va".into(), flood)]);
        let report = evaluate(&rpm_sandbox, &flood, "now");
        assert_eq!(report.findings.len(), MAX_FINDINGS + 1);
        assert_eq!(report.findings.last().unwrap().id, "integrity.more");
        assert_eq!(report.findings.last().unwrap().args["count"], "10");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(rpm_root).unwrap();
    }

    #[test]
    fn aide_is_only_claimed_when_it_is_set_up() {
        let (root, sandbox) = tree(&[("/usr/bin/aide", ""), ("/var/lib/aide/aide.db", "")]);
        let quiet = Fake(vec![(
            "/usr/bin/aide --check".into(),
            "### All files match AIDE database. ###\n".into(),
        )]);
        assert_eq!(
            evaluate(&sandbox, &quiet, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        let noisy = Fake(vec![(
            "/usr/bin/aide --check".into(),
            "added files:\nadded: /usr/local/bin/x\nchanged: /usr/bin/y\n".into(),
        )]);
        let report = evaluate(&sandbox, &noisy, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].args["count"], "2");
        let (bare_root, bare) = tree(&[]);
        // Only the package-manager result: AIDE is not claimed when it is
        // not set up.
        let bare_report = evaluate(&bare, &Fake::default(), "now");
        assert_eq!(bare_report.results.len(), 1);
        assert_eq!(bare_report.results[0].id, "integrity.packages");
        for r in [root, bare_root] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }
}
