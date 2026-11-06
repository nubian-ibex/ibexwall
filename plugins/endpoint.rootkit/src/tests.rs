// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-rk-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (path, text) in files {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }
    let sandbox = Sandbox::at(&root);
    (root, sandbox)
}

fn config(action: &str, every: &str) -> Config {
    Config {
        action: action.into(),
        every: every.into(),
    }
}

const RK: (&str, &str) = ("/usr/bin/rkhunter", "");
const CK: (&str, &str) = ("/usr/sbin/chkrootkit", "");

#[test]
fn nothing_is_planned_without_a_tool_and_the_error_says_nothing_is_installed_for_you() {
    let (root, sandbox) = tree(&[]);
    let err = plan(&sandbox, &config("scan", "")).unwrap_err().to_string();
    assert!(err.contains("installs no software"), "{err}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_scan_runs_what_is_installed_as_a_read_only_oneshot_and_a_schedule_adds_a_timer() {
    let (root, sandbox) = tree(&[RK, CK]);
    let ops = plan(&sandbox, &config("scan", "")).unwrap();
    let Op::FileWrite { content, .. } = &ops[1] else {
        panic!("{ops:?}")
    };
    for want in [
        "ExecStart=-/usr/bin/rkhunter --check --skip-keypress --nocolors --report-warnings-only",
        "ExecStart=-/usr/sbin/chkrootkit -q",
        "StandardOutput=append:/var/lib/ibexwall/rootkit/scan.out",
        "ProtectSystem=strict",
        "NoNewPrivileges=yes",
    ] {
        assert!(content.contains(want), "{want}\n{content}");
    }
    assert!(
        !content.contains("PrivateDevices"),
        "a rootkit scan has to see the real /dev"
    );
    assert!(matches!(
        ops.last(),
        Some(Op::SystemdUnit {
            action: UnitAction::Start,
            ..
        })
    ));
    assert!(!ops.iter().any(|o| matches!(
        o,
        Op::SystemdUnit {
            action: UnitAction::Enable,
            ..
        }
    )));
    let timed = plan(&sandbox, &config("schedule", "weekly")).unwrap();
    assert!(timed.iter().any(|o| matches!(
        o,
        Op::SystemdUnit {
            action: UnitAction::Enable,
            ..
        }
    )));
    assert!(timed.iter().any(
        |o| matches!(o, Op::FileWrite { content, .. } if content.contains("OnCalendar=weekly"))
    ));
    for bad in [config("run", ""), config("scan", "monthly")] {
        assert!(plan(&sandbox, &bad).is_err());
    }
    let (root2, only) = tree(&[CK]);
    let Op::FileWrite { content, .. } = &plan(&only, &config("scan", "")).unwrap()[1] else {
        panic!()
    };
    assert!(content.contains("chkrootkit") && !content.contains("rkhunter"));
    for r in [root, root2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn what_the_tools_flag_becomes_leads_and_the_rest_is_ignored() {
    let out = "\
[12:00:01] Warning: The command '/usr/bin/egrep' has been replaced by a script: /usr/bin/egrep: ASCII text executable
Warning: Hidden file found: /etc/.updated: ASCII text
Checking `ifconfig'... not infected
Searching for suspicious files in /dev... 
Checking `lkm'... INFECTED (PID 1234)
Warning: Hidden file found: /etc/.updated: ASCII text
";
    let found = parse(out);
    let summary: Vec<(&str, Severity)> = found.iter().map(|d| (d.tool, d.severity)).collect();
    assert_eq!(
        summary,
        [
            ("rkhunter", Severity::Medium),
            ("rkhunter", Severity::Medium),
            ("chkrootkit", Severity::Low),
            ("chkrootkit", Severity::High),
        ],
        "duplicates collapse and 'not infected' is not a finding"
    );
    assert!(found[0].text.starts_with("The command '/usr/bin/egrep'"));
    assert!(parse("").is_empty() && parse("all fine\n").is_empty());
    // Bounded, whatever a tool prints.
    let flood: String = (0..100).map(|n| format!("Warning: thing {n}\n")).collect();
    assert_eq!(parse(&flood).len(), MAX_FINDINGS);
    assert!(
        parse(&format!("Warning: {}\n", "x".repeat(1000)))[0]
            .text
            .len()
            <= 200
    );
}

#[test]
fn the_check_is_not_assessed_before_a_scan_passes_when_clean_and_fails_on_a_lead() {
    let (r1, never) = tree(&[RK]);
    let report = evaluate(&never, "x");
    assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
    let (r2, clean) = tree(&[RK, (OUT, "")]);
    assert_eq!(evaluate(&clean, "x").results[0].outcome, CheckOutcome::Pass);
    let (r3, flagged) = tree(&[RK, (OUT, "Warning: Hidden file found: /etc/.x\n")]);
    let report = evaluate(&flagged, "x");
    assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
    assert_eq!(
        report.results[0].severity,
        Severity::Low,
        "a lead weighs little"
    );
    let lead = report
        .findings
        .iter()
        .find(|f| f.id.starts_with("rootkit.rkhunter"))
        .unwrap();
    assert_eq!(lead.args["text"], "Hidden file found: /etc/.x");
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn the_note_names_what_is_there_and_the_install_command_when_nothing_is() {
    let (r1, none) = tree(&[("/etc/os-release", "ID=fedora\n")]);
    let n = evaluate(&none, "x")
        .findings
        .into_iter()
        .find(|f| f.id == "detect.rootkit")
        .unwrap();
    assert_eq!(n.summary_key, "detect-rootkit-none");
    assert_eq!(n.args["install"], "sudo dnf install rkhunter");
    let (r2, ready) = tree(&[RK]);
    assert_eq!(
        evaluate(&ready, "x")
            .findings
            .into_iter()
            .find(|f| f.id == "detect.rootkit")
            .unwrap()
            .summary_key,
        "detect-rootkit-ready"
    );
    let (r3, done) = tree(&[CK, (OUT, "")]);
    assert_eq!(
        evaluate(&done, "x")
            .findings
            .into_iter()
            .find(|f| f.id == "detect.rootkit")
            .unwrap()
            .summary_key,
        "detect-rootkit-scanned"
    );
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}
