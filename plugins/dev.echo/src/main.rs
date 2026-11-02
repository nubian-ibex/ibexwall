// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `dev.echo` plugin: serves the `com.ibexwall.Plugin` interface with
//! template-driven plans so the engine, supervisor and CLI can be
//! exercised end to end. Development/test only; never packaged.

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError};
use serde_json::Value;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Echo)) {
        eprintln!("ibexwall-plugin-echo: {err}");
        std::process::exit(1);
    }
}

struct Echo;

impl Plugin for Echo {
    fn id(&self) -> &'static str {
        "dev.echo"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![CheckResult {
                id: "dev.echo.check".into(),
                severity: Severity::Low,
                outcome: CheckOutcome::Fail,
            }],
            findings: vec![Finding {
                id: "dev.echo.check".into(),
                plugin: "dev.echo".into(),
                severity: Severity::Low,
                title_key: "dev-echo-finding-title".into(),
                summary_key: "dev-echo-finding-summary".into(),
                args: Default::default(),
                references: vec![],
                remediation: None,
                status: FindingStatus::Open,
                detected_at: "1970-01-01T00:00:00Z".into(),
            }],
        })
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let template = config
            .get("template")
            .and_then(Value::as_str)
            .unwrap_or("noop");
        plan_for(template).map_err(|reason| PluginError::invalid("template", reason))
    }
}

/// Templates the test suites drive through `PlanChange`.
fn plan_for(template: &str) -> Result<Vec<Op>, String> {
    let ops = match template {
        "noop" => vec![],
        "dropin" => vec![
            Op::FileWrite {
                path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
                content: "kernel.ibexwall_test = 1\n".into(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SysctlSet {
                key: "kernel.ibexwall_test".into(),
                value: "1".into(),
            },
        ],
        // File-only variant for real systems where the fake sysctl key
        // does not exist in /proc/sys.
        "dropin_file" => vec![Op::FileWrite {
            path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
            content: "# managed by IbexWall (vm test)\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        // Real, harmless sysctl for VM runs.
        "sysctl" => vec![
            Op::FileWrite {
                path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
                content: "vm.swappiness = 10\n".into(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SysctlSet {
                key: "vm.swappiness".into(),
                value: "10".into(),
            },
        ],
        "network" => vec![Op::FileWrite {
            path: "/etc/NetworkManager/conf.d/50-ibexwall-test.conf".into(),
            content: "# managed by IbexWall (dev test)\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        "slow" => vec![Op::Exec {
            path: "/usr/bin/sleep".into(),
            args: vec!["10".into()],
        }],
        "unit" => vec![Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: Some(true),
        }],
        // Deliberately outside the manifest: the core must refuse it.
        "out_of_manifest" => vec![Op::FileWrite {
            path: "/etc/ibexwall-refuse-me.conf".into(),
            content: "nope\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        other => return Err(format!("unknown template `{other}`")),
    };
    Ok(ops)
}
