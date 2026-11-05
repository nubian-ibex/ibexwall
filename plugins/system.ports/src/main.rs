// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.ports`: which services accept connections from other
//! computers. Read-only; parses `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! One scored check (`ports.exposed_services`) fails when any TCP service
//! listens on all interfaces. UDP wildcard sockets are reported as
//! informational findings only: DHCP, mDNS and similar are normal on
//! desktops and would make the score noisy.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Reference, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

mod procnet;

use procnet::Proto;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Ports)) {
        eprintln!("ibexwall-plugin-ports: {err}");
        std::process::exit(1);
    }
}

struct Ports;

impl Plugin for Ports {
    fn id(&self) -> &'static str {
        "system.ports"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// Runs the check against any tree (real system, sandbox or fixture).
pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let sockets = procnet::exposed_sockets(sandbox);
    let owners = procnet::process_names(sandbox, &sockets);

    let mut findings = Vec::new();
    let mut tcp_exposed = false;
    let mut seen: BTreeMap<(Proto, u16), ()> = BTreeMap::new();
    for socket in &sockets {
        // One finding per proto/port, even when listening on IPv4 and IPv6.
        if seen.insert((socket.proto, socket.port), ()).is_some() {
            continue;
        }
        let tcp = matches!(socket.proto, Proto::Tcp);
        tcp_exposed |= tcp;
        let process = owners.get(&socket.inode).cloned().unwrap_or_default();
        let mut args = BTreeMap::new();
        args.insert("port".to_string(), socket.port.to_string());
        args.insert("proto".to_string(), socket.proto.label().to_string());
        // Process names are not trusted (a program picks its own name):
        // they travel as an argument, never as markup or instructions.
        args.insert("process".to_string(), process);
        let (suffix, severity) = if tcp {
            ("exposed", Severity::Medium)
        } else {
            ("udp", Severity::Info)
        };
        findings.push(Finding {
            id: format!(
                "ports.{}.{}",
                socket.proto.label().to_lowercase(),
                socket.port
            ),
            plugin: "system.ports".into(),
            severity,
            title_key: format!("ports-{suffix}-title"),
            summary_key: format!("ports-{suffix}-summary"),
            args,
            references: Vec::<Reference>::new(),
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }

    let outcome = if tcp_exposed {
        CheckOutcome::Fail
    } else {
        CheckOutcome::Pass
    };
    CheckReport {
        results: vec![CheckResult {
            id: "ports.exposed_services".into(),
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
            "ibx-ports-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    #[test]
    fn loopback_only_listeners_pass() {
        let (root, sandbox) = tree(&[(
            "/proc/net/tcp",
            &format!(
                "{HEADER}   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0\n"
            ),
        )]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert!(report.findings.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn wildcard_tcp_listener_fails_and_names_the_port() {
        let (root, sandbox) = tree(&[(
            "/proc/net/tcp",
            &format!(
                "{HEADER}   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0\n"
            ),
        )]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].args["port"], "22");
        assert_eq!(report.findings[0].args["proto"], "TCP");
        assert_eq!(report.findings[0].severity, Severity::Medium);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_stack_listener_is_one_finding() {
        let (root, sandbox) = tree(&[
            (
                "/proc/net/tcp",
                &format!(
                    "{HEADER}   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
                ),
            ),
            (
                "/proc/net/tcp6",
                &format!(
                    "{HEADER}   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0\n"
                ),
            ),
        ]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(report.findings.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn udp_wildcards_are_informational_and_do_not_fail_the_check() {
        let (root, sandbox) = tree(&[(
            "/proc/net/udp",
            &format!(
                "{HEADER}  12: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3 2 0000000000000000 0\n"
            ),
        )]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert_eq!(report.findings[0].args["proto"], "UDP");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_proc_net_does_not_claim_a_pass_with_findings() {
        let (root, sandbox) = tree(&[("/etc/hostname", "x")]);
        let report = evaluate(&sandbox, "t");
        // Nothing readable: no findings. (The core marks plugin errors.)
        assert!(report.findings.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Runs the plugin against the real files collected from each distro
    /// (`cargo xtask vm-test --distro <id> --phase fixtures`) and compares
    /// with the reviewed `expected-ports.json` next to them. Regenerate
    /// with `UPDATE_GOLDEN=1` and review the diff before committing.
    #[test]
    fn real_distro_fixtures_match_the_reviewed_expectations() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures");
        let mut checked = 0;
        for entry in std::fs::read_dir(&base).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let report = evaluate(&Sandbox::at(&dir), "t");
            let mut actual = std::collections::BTreeMap::new();
            for result in &report.results {
                actual.insert(result.id.clone(), format!("{:?}", result.outcome));
            }
            for finding in &report.findings {
                if finding.plugin == "system.ports" {
                    actual.insert(
                        format!("finding:{}", finding.id),
                        format!("{:?}", finding.severity),
                    );
                }
            }
            let golden = dir.join("expected-ports.json");
            let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
            if std::env::var_os("UPDATE_GOLDEN").is_some() {
                std::fs::write(&golden, &text).unwrap();
            }
            let expected = std::fs::read_to_string(&golden).unwrap_or_else(|_| {
                panic!("missing {}; run with UPDATE_GOLDEN=1", golden.display())
            });
            assert_eq!(text, expected, "fixture {} drifted", dir.display());
            checked += 1;
        }
        assert!(checked >= 1, "no fixtures found under {}", base.display());
    }
}
