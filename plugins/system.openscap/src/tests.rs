// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "ibx-scap-{}-{}",
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

const FEDORA: (&str, &str) = ("/etc/os-release", "ID=fedora\nVERSION_ID=45\n");
const DS: (&str, &str) = (
    "/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml",
    "<Profile id=\"xccdf_org.ssgproject.content_profile_standard\"/><Profile id=\"xccdf_org.ssgproject.content_profile_anssi_bp28_minimal\"/>",
);
const RESULTS_XML: &str = r#"<?xml version="1.0"?><Benchmark><TestResult id="x">
<profile idref="xccdf_org.ssgproject.content_profile_standard"/>
<rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" time="t" severity="high" weight="1.0"><result>fail</result></rule-result>
<rule-result idref="xccdf_org.ssgproject.content_rule_audit_rules_time_adjtimex" severity="medium"><result>fail</result></rule-result>
<rule-result idref="xccdf_org.ssgproject.content_rule_banner_etc_issue" severity="low"><result>fail</result></rule-result>
<rule-result idref="xccdf_org.ssgproject.content_rule_a_good_one" severity="high"><result>pass</result></rule-result>
<rule-result idref="xccdf_org.ssgproject.content_rule_skipped" severity="low"><result>notapplicable</result></rule-result>
<rule-result idref="xccdf_org.ssgproject.content_rule_odd" severity="low"><result>error</result></rule-result>
</TestResult></Benchmark>"#;

fn scan(profile: &str) -> Config {
    Config {
        action: "scan".into(),
        profile: profile.into(),
        every: String::new(),
    }
}

#[test]
fn the_content_file_is_picked_from_the_distribution_and_never_from_a_path() {
    let (r1, fedora) = tree(&[FEDORA, DS]);
    assert_eq!(content_file(&fedora).as_deref(), Some("ssg-fedora-ds.xml"));
    let (r2, ubuntu) = tree(&[
        ("/etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
        ("/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml", ""),
    ]);
    assert_eq!(
        content_file(&ubuntu).as_deref(),
        Some("ssg-ubuntu2404-ds.xml")
    );
    let (r3, debian) = tree(&[
        ("/etc/os-release", "ID=debian\nVERSION_ID=\"13\"\n"),
        ("/usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml", ""),
    ]);
    assert_eq!(
        content_file(&debian).as_deref(),
        Some("ssg-debian13-ds.xml")
    );
    let (r4, arch) = tree(&[("/etc/os-release", "ID=arch\n")]);
    assert_eq!(content_file(&arch), None);
    assert!(
        serde_json::from_value::<Config>(
            serde_json::json!({ "action": "scan", "content": "/tmp/x.xml" })
        )
        .is_err()
    );
    for r in [r1, r2, r3, r4] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn a_scan_names_a_profile_that_exists_in_the_content_and_runs_oscap_as_a_oneshot() {
    let (root, sandbox) = tree(&[FEDORA, DS, (OSCAP, "")]);
    let ops = plan(&sandbox, &scan("")).unwrap();
    let Op::FileWrite { content, .. } = &ops[1] else {
        panic!("{ops:?}")
    };
    assert!(
        content.contains("ExecStart=-/usr/bin/oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard --results /var/lib/ibexwall/openscap/results.xml /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml"),
        "{content}"
    );
    assert!(content.contains("Type=oneshot") && content.contains("ProtectSystem=strict"));
    assert!(plan(&sandbox, &scan("anssi_bp28_minimal")).is_ok());
    for bad in ["nonexistent", "Standard", "a b", "../x", &"a".repeat(80)] {
        assert!(plan(&sandbox, &scan(bad)).is_err(), "{bad}");
    }
    let timed = plan(
        &sandbox,
        &Config {
            action: "schedule".into(),
            profile: String::new(),
            every: "weekly".into(),
        },
    )
    .unwrap();
    assert!(timed.iter().any(|o| matches!(
        o,
        Op::SystemdUnit {
            action: UnitAction::Enable,
            ..
        }
    )));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn nothing_is_planned_without_the_scanner_or_its_content() {
    let (r1, none) = tree(&[FEDORA]);
    assert!(
        plan(&none, &scan(""))
            .unwrap_err()
            .to_string()
            .contains("OpenSCAP is not installed")
    );
    let (r2, no_content) = tree(&[FEDORA, (OSCAP, "")]);
    assert!(
        plan(&no_content, &scan(""))
            .unwrap_err()
            .to_string()
            .contains("content")
    );
    for r in [r1, r2] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn results_become_counts_and_failed_rules_worst_first() {
    let o = parse(RESULTS_XML);
    assert_eq!(o.profile, "standard");
    assert_eq!((o.passed, o.failed, o.other), (1, 3, 1));
    assert_eq!(
        o.failures,
        [
            ("sshd_disable_root_login".to_string(), Severity::High),
            ("audit_rules_time_adjtimex".to_string(), Severity::Medium),
            ("banner_etc_issue".to_string(), Severity::Low),
        ]
    );
    assert_eq!(parse(""), Outcome::default());
    assert_eq!(parse("<rule-result>").failed, 0);
}

#[test]
fn the_check_waits_for_a_scan_then_passes_or_fails_and_lists_rules_as_findings() {
    let (r1, never) = tree(&[FEDORA, DS, (OSCAP, "")]);
    let report = evaluate(&never, "x");
    assert_eq!(report.results[0].outcome, CheckOutcome::NotAssessed);
    assert_eq!(
        report
            .findings
            .iter()
            .find(|f| f.id == "detect.openscap")
            .unwrap()
            .summary_key,
        "detect-openscap-ready"
    );
    let (r2, done) = tree(&[FEDORA, DS, (OSCAP, ""), (RESULTS, RESULTS_XML)]);
    let report = evaluate(&done, "x");
    assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
    assert_eq!(report.results[0].severity, Severity::Low);
    let worst = report
        .findings
        .iter()
        .find(|f| f.id == "openscap.sshd_disable_root_login")
        .unwrap();
    assert_eq!(
        (worst.severity, worst.args["profile"].as_str()),
        (Severity::High, "standard")
    );
    let note = report
        .findings
        .iter()
        .find(|f| f.id == "detect.openscap")
        .unwrap();
    assert_eq!(
        (note.summary_key.as_str(), note.args["failed"].as_str()),
        ("detect-openscap-scanned", "3")
    );
    let clean = RESULTS_XML.replace("<result>fail</result>", "<result>pass</result>");
    let (r3, passing) = tree(&[FEDORA, DS, (OSCAP, ""), (RESULTS, &clean)]);
    assert_eq!(
        evaluate(&passing, "x").results[0].outcome,
        CheckOutcome::Pass
    );
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}

#[test]
fn the_note_gives_the_distributions_install_command_or_names_the_missing_content() {
    let (r1, none) = tree(&[FEDORA]);
    let n = evaluate(&none, "x")
        .findings
        .into_iter()
        .find(|f| f.id == "detect.openscap")
        .unwrap();
    assert_eq!(
        (n.summary_key.as_str(), n.args["install"].as_str()),
        ("detect-openscap-none", "sudo dnf install openscap-scanner")
    );
    let (r2, arch) = tree(&[("/etc/os-release", "ID=arch\n")]);
    let n = evaluate(&arch, "x")
        .findings
        .into_iter()
        .find(|f| f.id == "detect.openscap")
        .unwrap();
    assert_eq!(n.args["install"], "sudo pacman -S openscap");
    let (r3, bare) = tree(&[FEDORA, (OSCAP, "")]);
    assert_eq!(
        evaluate(&bare, "x")
            .findings
            .into_iter()
            .find(|f| f.id == "detect.openscap")
            .unwrap()
            .summary_key,
        "detect-openscap-no-content"
    );
    for r in [r1, r2, r3] {
        std::fs::remove_dir_all(r).unwrap();
    }
}
