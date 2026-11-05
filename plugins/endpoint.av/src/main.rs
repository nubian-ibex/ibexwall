// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `endpoint.av`: ClamAV and YARA on folders, on demand or on a schedule.
//! The scan is a oneshot unit the plugin owns; its output goes to a log the
//! unit empties at each run, and the check turns that log into findings,
//! so what is reported is what the scanners said, not the plugin's opinion
//! of a file. IbexWall installs neither scanner (the check says what is
//! missing). Scan paths are explicit: the daemon's own unit hides /home, so
//! the plugin cannot discover Downloads folders (F10 gives plugins their own
//! units). File names and signature names are Fluent arguments only.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

const SERVICE_UNIT: &str = "ibexwall-av-scan.service";
const TIMER_UNIT: &str = "ibexwall-av-scan.timer";
const SERVICE_FILE: &str = "/etc/systemd/system/ibexwall-av-scan.service";
const TIMER_FILE: &str = "/etc/systemd/system/ibexwall-av-scan.timer";
const RULES_FILE: &str = "/etc/ibexwall/av/rules.yar";
const CONFIG_FILE: &str = "/etc/ibexwall/av/config.json";
/// Two logs, each where its writer may write under SELinux: a confined
/// clamscan writes its own report in ClamAV's state directory (which every
/// package creates); YARA's output goes through systemd to a file in ours.
const CLAM_LOG: &str = "/var/lib/clamav/ibexwall-av-scan.log";
const YARA_LOG: &str = "/var/lib/ibexwall/av/yara.log";
const CLAMSCAN: &str = "/usr/bin/clamscan";
const YARA: &str = "/usr/bin/yara";
const MAX_FINDINGS: usize = 20;
const MAX_PATHS: usize = 8;

/// The test string every scanner knows (https://www.eicar.org); this rule
/// ships so YARA does something useful out of the box.
const RULES: &str = "// Managed by IbexWall (endpoint.av).\nrule EICAR_Test_File {\n  strings:\n    $e = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\"\n  condition:\n    $e\n}\n";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Av)) {
        eprintln!("ibexwall-plugin-av: {err}");
        std::process::exit(1);
    }
}

struct Av;

fn many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(text) => vec![text],
        OneOrMany::Many(list) => list,
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    /// `scan` (now) or `schedule` (a timer, and a first run now).
    action: String,
    #[serde(deserialize_with = "many")]
    paths: Vec<String>,
    /// A ClamAV database file or directory to use instead of the default.
    database: String,
    /// `daily`, `weekly` or `hourly`.
    every: String,
}

impl Plugin for Av {
    fn id(&self) -> &'static str {
        "endpoint.av"
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

/// An absolute path made only of characters that need no quoting in a unit.
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("..")
        && path.len() <= 200
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+'))
}

fn service_unit(paths: &[String], database: &str, yara: bool) -> String {
    let mut out = String::from(
        "# Managed by IbexWall (endpoint.av).\n[Unit]\nDescription=IbexWall antimalware scan\n\n[Service]\nType=oneshot\nStateDirectory=ibexwall/av\nStandardOutput=append:/var/lib/ibexwall/av/yara.log\nNice=10\nIOSchedulingClass=idle\nProtectSystem=strict\nReadWritePaths=-/tmp -/var/tmp /var/lib/clamav\nProtectHome=read-only\nNoNewPrivileges=yes\nPrivateDevices=yes\n",
    );
    // `append:` reopens the file for every ExecStart (truncating would let
    // the second scanner erase the first one's findings), so the log is
    // emptied once, up front.
    out.push_str(
        "ExecStartPre=/usr/bin/truncate -s 0 /var/lib/ibexwall/av/yara.log\nExecStartPre=-/usr/bin/rm -f /var/lib/clamav/ibexwall-av-scan.log\n",
    );
    // A scanner exits non-zero when it finds something: that is the result,
    // not a failure of the unit, hence the leading `-`.
    let db = if database.is_empty() {
        String::new()
    } else {
        format!(" -d {database}")
    };
    out.push_str(&format!(
        "ExecStart=-{CLAMSCAN} -r -i --no-summary --log={CLAM_LOG}{db} {}\n",
        paths.join(" ")
    ));
    if yara {
        for path in paths {
            out.push_str(&format!("ExecStart=-{YARA} -r {RULES_FILE} {path}\n"));
        }
    }
    out
}

fn timer_unit(every: &str) -> String {
    format!(
        "# Managed by IbexWall (endpoint.av).\n[Unit]\nDescription=IbexWall antimalware scan, {every}\n\n[Timer]\nOnCalendar={every}\nPersistent=true\nRandomizedDelaySec=15m\n\n[Install]\nWantedBy=timers.target\n"
    )
}

fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let schedule = match config.action.as_str() {
        "scan" => false,
        "schedule" => true,
        _ => {
            return Err(PluginError::invalid(
                "action",
                "action is `scan` or `schedule`",
            ));
        }
    };
    let clam = sandbox.exists(CLAMSCAN);
    let yara = sandbox.exists(YARA);
    if !clam && !yara {
        return Err(PluginError::invalid(
            "action",
            "neither ClamAV nor YARA is installed; IbexWall installs no software",
        ));
    }
    let paths: Vec<String> = if config.paths.is_empty() {
        vec!["/tmp".into(), "/var/tmp".into()]
    } else {
        config.paths.clone()
    };
    if paths.len() > MAX_PATHS {
        return Err(PluginError::invalid("paths", "at most 8 folders"));
    }
    if let Some(bad) = paths.iter().find(|p| !safe_path(p)) {
        return Err(PluginError::invalid(
            "paths",
            format!("`{bad}` is not a plain absolute path"),
        ));
    }
    if !config.database.is_empty() && !safe_path(&config.database) {
        return Err(PluginError::invalid(
            "database",
            "not a plain absolute path",
        ));
    }
    let every = if config.every.is_empty() {
        "daily"
    } else {
        config.every.as_str()
    };
    if !matches!(every, "hourly" | "daily" | "weekly") {
        return Err(PluginError::invalid("every", "hourly, daily or weekly"));
    }
    let file = |path: &str, content: String| Op::FileWrite {
        path: path.into(),
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let record = serde_json::json!({ "paths": paths, "database": config.database, "clamav": clam, "yara": yara });
    let mut ops = vec![
        // systemd opens YARA's log before it makes a state directory, so the
        // directory has to exist when the unit first runs.
        file(
            "/var/lib/ibexwall/av/.managed",
            "# Managed by IbexWall (endpoint.av).\n".into(),
        ),
        file(SERVICE_FILE, service_unit(&paths, &config.database, yara)),
        file(CONFIG_FILE, format!("{record}\n")),
    ];
    if yara {
        ops.push(file(RULES_FILE, RULES.into()));
    }
    if schedule {
        ops.push(file(TIMER_FILE, timer_unit(every)));
        ops.push(Op::SystemdUnit {
            unit: TIMER_UNIT.into(),
            action: UnitAction::Enable,
            now: Some(true),
        });
    }
    // The first run: a oneshot, so the start returns when the scan is done.
    ops.push(Op::SystemdUnit {
        unit: SERVICE_UNIT.into(),
        action: UnitAction::Start,
        now: None,
    });
    Ok(ops)
}

#[derive(Debug, PartialEq)]
struct Detection {
    path: String,
    signature: String,
}

/// ClamAV prints `path: Signature FOUND`; YARA prints `Rule path`.
fn parse_log(text: &str) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        let found = if let Some(rest) = line.strip_suffix(" FOUND") {
            rest.rsplit_once(": ").map(|(path, sig)| Detection {
                path: path.to_string(),
                signature: sig.to_string(),
            })
        } else if let Some((rule, path)) = line.split_once(' ') {
            (path.starts_with('/') && rule.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
                .then(|| Detection {
                    path: path.to_string(),
                    signature: rule.to_string(),
                })
        } else {
            None
        };
        if let Some(d) = found
            && !out.contains(&d)
        {
            out.push(d);
        }
    }
    out
}

/// SELinux enforcing and `antivirus_can_scan_system` off.
fn selinux_blocks_scanning(sandbox: &Sandbox) -> bool {
    let enforcing = sandbox
        .read("/sys/fs/selinux/enforce")
        .is_some_and(|t| t.trim() == "1");
    let allowed = sandbox
        .read("/sys/fs/selinux/booleans/antivirus_can_scan_system")
        .map(|t| t.trim().starts_with('1'));
    enforcing && allowed == Some(false)
}

fn has_signatures(sandbox: &Sandbox) -> bool {
    let custom = sandbox
        .read(CONFIG_FILE)
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v["database"].as_str().map(String::from))
        .filter(|d| !d.is_empty());
    if let Some(db) = custom {
        return sandbox.exists(&db);
    }
    ["/var/lib/clamav", "/usr/share/clamav"].iter().any(|dir| {
        sandbox.list(dir).iter().any(|n| {
            [".cvd", ".cld", ".hdb", ".hsb", ".ndb", ".ldb", ".cud"]
                .iter()
                .any(|ext| n.ends_with(ext))
        })
    })
}

fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let clam = sandbox.exists(CLAMSCAN);
    let yara = sandbox.exists(YARA);
    let finding =
        |id: &str, severity, title: &str, summary: &str, args: BTreeMap<String, String>| Finding {
            id: id.into(),
            plugin: "endpoint.av".into(),
            severity,
            title_key: title.into(),
            summary_key: summary.into(),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        };
    let mut findings = Vec::new();
    let mut results = Vec::new();

    if !clam && !yara {
        findings.push(finding(
            "av.no_scanner",
            Severity::Info,
            "av-noscanner-title",
            "av-noscanner-summary",
            BTreeMap::new(),
        ));
        results.push(CheckResult {
            id: "av.scanner".into(),
            severity: Severity::Medium,
            outcome: CheckOutcome::NotAssessed,
        });
        return CheckReport { results, findings };
    }
    results.push(CheckResult {
        id: "av.scanner".into(),
        severity: Severity::Medium,
        outcome: CheckOutcome::Pass,
    });

    // Under SELinux a confined ClamAV cannot read other people's files until
    // this boolean is on: the scan would "work" and see nothing.
    if clam && selinux_blocks_scanning(sandbox) {
        findings.push(finding(
            "av.selinux",
            Severity::Medium,
            "av-selinux-title",
            "av-selinux-summary",
            BTreeMap::new(),
        ));
        results.push(CheckResult {
            id: "av.selinux".into(),
            severity: Severity::Medium,
            outcome: CheckOutcome::Fail,
        });
    }

    if clam && !has_signatures(sandbox) {
        findings.push(finding(
            "av.no_signatures",
            Severity::Medium,
            "av-nosignatures-title",
            "av-nosignatures-summary",
            BTreeMap::new(),
        ));
        results.push(CheckResult {
            id: "av.signatures".into(),
            severity: Severity::Medium,
            outcome: CheckOutcome::Fail,
        });
    }

    let logs: Vec<String> = [CLAM_LOG, YARA_LOG]
        .iter()
        .filter_map(|p| sandbox.read(p))
        .collect();
    let outcome = match logs.is_empty() {
        true => CheckOutcome::NotAssessed, // never scanned
        false => {
            let detections = parse_log(&logs.join("\n"));
            for d in detections.iter().take(MAX_FINDINGS) {
                findings.push(finding(
                    "av.infected",
                    Severity::High,
                    "av-infected-title",
                    "av-infected-summary",
                    BTreeMap::from([
                        ("path".to_string(), d.path.clone()),
                        ("signature".to_string(), d.signature.clone()),
                    ]),
                ));
            }
            if detections.len() > MAX_FINDINGS {
                findings.push(finding(
                    "av.more",
                    Severity::High,
                    "av-more-title",
                    "av-more-summary",
                    BTreeMap::from([(
                        "count".to_string(),
                        (detections.len() - MAX_FINDINGS).to_string(),
                    )]),
                ));
            }
            if detections.is_empty() {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            }
        }
    };
    results.push(CheckResult {
        id: "av.detections".into(),
        severity: Severity::High,
        outcome,
    });
    CheckReport { results, findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-av-{}-{}",
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

    fn cfg(value: Value) -> Config {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn the_log_of_both_scanners_becomes_detections() {
        let text = "/home/ana/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND\nEICAR_Test_File /home/ana/Downloads/eicar.com\nEICAR_Test_File /tmp/other\n/tmp/ok.txt: OK\nwarning: something odd\n";
        let found = parse_log(text);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].signature, "Win.Test.EICAR_HDB-1");
        assert_eq!(found[1].signature, "EICAR_Test_File");
        assert!(parse_log("").is_empty());
        // The same file twice from one scanner is one finding.
        assert_eq!(parse_log("/a: X FOUND\n/a: X FOUND\n").len(), 1);
    }

    #[test]
    fn the_scan_plan_is_an_owned_oneshot_unit_with_fixed_argv() {
        let (root, sandbox) = tree(&[(CLAMSCAN, ""), (YARA, "")]);
        let ops = plan(
            &sandbox,
            &cfg(json!({ "action": "scan", "paths": ["/home/ana/Downloads"], "database": "/var/lib/ibexwall/av/db" })),
        )
        .unwrap();
        let Op::FileWrite { content, path, .. } = &ops[1] else {
            panic!()
        };
        assert_eq!(path, SERVICE_FILE);
        assert!(content.contains("Type=oneshot") && content.contains("ProtectSystem=strict"));
        // ClamAV makes a temporary directory for every scan.
        assert!(content.contains("ReadWritePaths=-/tmp -/var/tmp /var/lib/clamav"));
        assert!(content.contains("ExecStart=-/usr/bin/clamscan -r -i --no-summary --log=/var/lib/clamav/ibexwall-av-scan.log -d /var/lib/ibexwall/av/db /home/ana/Downloads"));
        assert!(content.contains(
            "ExecStart=-/usr/bin/yara -r /etc/ibexwall/av/rules.yar /home/ana/Downloads"
        ));
        assert!(content.contains("StandardOutput=append:/var/lib/ibexwall/av/yara.log"));
        assert!(content.contains("--log=/var/lib/clamav/ibexwall-av-scan.log"));
        assert!(
            content.contains("ExecStartPre=/usr/bin/truncate -s 0 /var/lib/ibexwall/av/yara.log")
        );
        assert!(
            ops.iter()
                .any(|o| matches!(o, Op::FileWrite { path, .. } if path == RULES_FILE))
        );
        assert!(
            matches!(ops.last(), Some(Op::SystemdUnit { unit, action: UnitAction::Start, .. }) if unit == SERVICE_UNIT)
        );
        assert!(
            !ops.iter()
                .any(|o| matches!(o, Op::SystemdUnit { unit, .. } if unit == TIMER_UNIT))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_schedule_adds_an_enabled_timer_and_a_scanner_that_is_missing_is_left_out() {
        let (root, sandbox) = tree(&[(CLAMSCAN, "")]);
        let ops = plan(
            &sandbox,
            &cfg(json!({ "action": "schedule", "every": "weekly" })),
        )
        .unwrap();
        let timer = ops.iter().find_map(|o| match o {
            Op::FileWrite { path, content, .. } if path == TIMER_FILE => Some(content.clone()),
            _ => None,
        });
        assert!(timer.unwrap().contains("OnCalendar=weekly"));
        assert!(ops.iter().any(|o| matches!(o, Op::SystemdUnit { unit, action: UnitAction::Enable, .. } if unit == TIMER_UNIT)));
        // No YARA here: no rules file, no yara line, default folders.
        let Op::FileWrite { content, .. } = &ops[1] else {
            panic!()
        };
        assert!(!content.contains("/usr/bin/yara") && content.contains("/tmp /var/tmp"));
        assert!(
            !ops.iter()
                .any(|o| matches!(o, Op::FileWrite { path, .. } if path == RULES_FILE))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_paths_and_missing_scanners_are_refused() {
        let (root, sandbox) = tree(&[(CLAMSCAN, "")]);
        for bad in [
            "relative",
            "/tmp/a b",
            "/tmp/../etc",
            "/tmp/$(id)",
            "/tmp/a;b",
            "/tmp/a\nExecStart=/bin/sh",
            "",
        ] {
            let c = cfg(json!({ "action": "scan", "paths": [bad] }));
            if bad.is_empty() {
                continue;
            }
            assert!(plan(&sandbox, &c).is_err(), "{bad:?}");
        }
        assert!(
            plan(
                &sandbox,
                &cfg(json!({ "action": "scan", "database": "relative" }))
            )
            .is_err()
        );
        assert!(
            plan(
                &sandbox,
                &cfg(json!({ "action": "schedule", "every": "minutely" }))
            )
            .is_err()
        );
        assert!(plan(&sandbox, &cfg(json!({ "action": "x" }))).is_err());
        let many: Vec<String> = (0..9).map(|n| format!("/tmp/d{n}")).collect();
        assert!(plan(&sandbox, &cfg(json!({ "action": "scan", "paths": many }))).is_err());
        let (bare, none) = tree(&[]);
        let error = plan(&none, &cfg(json!({ "action": "scan" }))).unwrap_err();
        assert!(error.to_string().contains("installs no software"));
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(bare).unwrap();
    }

    #[test]
    fn the_check_says_what_is_missing_and_never_claims_a_scan_that_did_not_happen() {
        let (r1, none) = tree(&[]);
        let report = evaluate(&none, "now");
        assert_eq!(report.findings[0].id, "av.no_scanner");
        assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);

        let (r2, no_db) = tree(&[(CLAMSCAN, "")]);
        let report = evaluate(&no_db, "now");
        assert!(report.findings.iter().any(|f| f.id == "av.no_signatures"));
        assert_eq!(
            report.results.last().unwrap().outcome,
            CheckOutcome::NotAssessed
        );

        let (r3, ready) = tree(&[(CLAMSCAN, ""), ("/var/lib/clamav/main.cvd", "x")]);
        let report = evaluate(&ready, "now");
        assert!(
            report.findings.is_empty(),
            "scanner and signatures, never scanned: nothing claimed"
        );
        for r in [r1, r2, r3] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    #[test]
    fn selinux_in_the_way_of_the_scanner_is_named() {
        let blocked = [
            (CLAMSCAN, ""),
            ("/var/lib/clamav/main.cvd", "x"),
            ("/sys/fs/selinux/enforce", "1"),
            (
                "/sys/fs/selinux/booleans/antivirus_can_scan_system",
                "0 0\n",
            ),
        ];
        let (r1, sandbox) = tree(&blocked);
        let report = evaluate(&sandbox, "now");
        assert!(report.findings.iter().any(|f| f.id == "av.selinux"));
        let (r2, allowed) = tree(&[
            (CLAMSCAN, ""),
            ("/var/lib/clamav/main.cvd", "x"),
            ("/sys/fs/selinux/enforce", "1"),
            (
                "/sys/fs/selinux/booleans/antivirus_can_scan_system",
                "1 1\n",
            ),
        ]);
        assert!(evaluate(&allowed, "now").findings.is_empty());
        // Permissive, or no SELinux at all: not this plugin's business.
        let (r3, permissive) = tree(&[
            (CLAMSCAN, ""),
            ("/var/lib/clamav/main.cvd", "x"),
            ("/sys/fs/selinux/enforce", "0"),
            (
                "/sys/fs/selinux/booleans/antivirus_can_scan_system",
                "0 0\n",
            ),
        ]);
        assert!(evaluate(&permissive, "now").findings.is_empty());
        for r in [r1, r2, r3] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    #[test]
    fn detections_in_the_log_become_high_findings_with_the_data_as_arguments() {
        let (root, sandbox) = tree(&[
            (CLAMSCAN, ""),
            ("/var/lib/clamav/daily.cld", "x"),
            (
                CLAM_LOG,
                "/home/ana/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results.last().unwrap().outcome, CheckOutcome::Fail);
        let f = &report.findings[0];
        assert_eq!((f.id.as_str(), f.severity), ("av.infected", Severity::High));
        assert_eq!(f.args["path"], "/home/ana/Downloads/eicar.com");
        assert_eq!(f.args["signature"], "Win.Test.EICAR_HDB-1");
        std::fs::write(root.join(CLAM_LOG.trim_start_matches('/')), "").unwrap();
        assert_eq!(
            evaluate(&sandbox, "now").results.last().unwrap().outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
