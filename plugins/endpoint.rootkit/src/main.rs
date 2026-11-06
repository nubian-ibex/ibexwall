// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `endpoint.rootkit`: rkhunter and chkrootkit. The plan writes one oneshot
//! unit (and a timer when asked) that runs whichever is installed as root
//! and leaves their output in IbexWall's state directory; the check reads
//! that output later. IbexWall installs neither tool: when one is missing the
//! person gets the distribution's own command.
//!
//! What these tools print is a lead, not a verdict: both are known for false
//! alarms after a package update. Findings say so, are capped, and never
//! lower the score by more than a low-severity check.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction,
};
use ibexwall_sdk::detect::{detected, install_command};
use ibexwall_sdk::scanner::{Service, clean_line, schedule, service_unit, timer_unit};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const ID: &str = "endpoint.rootkit";
const SERVICE_UNIT: &str = "ibexwall-rootkit-scan.service";
const TIMER_UNIT: &str = "ibexwall-rootkit-scan.timer";
const SERVICE_FILE: &str = "/etc/systemd/system/ibexwall-rootkit-scan.service";
const TIMER_FILE: &str = "/etc/systemd/system/ibexwall-rootkit-scan.timer";
const MANAGED: &str = "/var/lib/ibexwall/rootkit/.managed";
const OUT: &str = "/var/lib/ibexwall/rootkit/scan.out";
const RKHUNTER_LOG: &str = "/var/lib/ibexwall/rootkit/rkhunter.log";
const MAX_FINDINGS: usize = 20;

const RKHUNTER: &[&str] = &["/usr/bin/rkhunter"];
const CHKROOTKIT: &[&str] = &["/usr/sbin/chkrootkit", "/usr/bin/chkrootkit"];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `scan` or `schedule`.
    pub action: String,
    /// `hourly`, `daily` (the default) or `weekly`.
    pub every: String,
}

struct Rootkit;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Rootkit)) {
        eprintln!("ibexwall-plugin-rootkit: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Rootkit {
    fn id(&self) -> &'static str {
        ID
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

fn installed(sandbox: &Sandbox, paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|p| sandbox.exists(p))
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let timer = match config.action.as_str() {
        "scan" => false,
        "schedule" => true,
        _ => {
            return Err(PluginError::invalid(
                "action",
                "action is `scan` or `schedule`",
            ));
        }
    };
    let every = schedule(&config.every)
        .ok_or_else(|| PluginError::invalid("every", "hourly, daily or weekly"))?;
    let rkhunter = installed(sandbox, RKHUNTER);
    let chkrootkit = installed(sandbox, CHKROOTKIT);
    if rkhunter.is_none() && chkrootkit.is_none() {
        return Err(PluginError::invalid(
            "action",
            "neither rkhunter nor chkrootkit is installed; IbexWall installs no software",
        ));
    }
    let mut commands =
        vec!["-/usr/bin/truncate -s 0 /var/lib/ibexwall/rootkit/scan.out".to_string()];
    if let Some(path) = rkhunter {
        commands.push(format!(
            "-{path} --check --skip-keypress --nocolors --report-warnings-only --logfile {RKHUNTER_LOG}"
        ));
    }
    if let Some(path) = chkrootkit {
        commands.push(format!("-{path} -q"));
    }
    // The truncate runs first and is not a scanner; the output of the rest
    // goes to one file.
    let mut unit = service_unit(&Service {
        plugin: ID,
        description: "IbexWall rootkit scan",
        state_dir: "ibexwall/rootkit",
        writable: if rkhunter.is_some() {
            &["/var/lib/rkhunter", "/var/tmp"]
        } else {
            &["/var/tmp"]
        },
        commands: &commands,
        timeout: "30min",
        host_view: true,
        no_new_privileges: true,
    });
    unit = unit.replace(
        "Type=oneshot\n",
        &format!("Type=oneshot\nStandardOutput=append:{OUT}\n"),
    );
    let file = |path: &str, content: String| Op::FileWrite {
        path: path.into(),
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![
        // systemd opens the output file before it makes the state directory.
        file(
            MANAGED,
            "# Managed by IbexWall (endpoint.rootkit).\n".into(),
        ),
        file(SERVICE_FILE, unit),
    ];
    if timer {
        ops.push(file(
            TIMER_FILE,
            timer_unit(ID, "IbexWall rootkit scan", every),
        ));
        ops.push(Op::SystemdUnit {
            unit: TIMER_UNIT.into(),
            action: UnitAction::Enable,
            now: Some(true),
        });
    }
    ops.push(Op::SystemdUnit {
        unit: SERVICE_UNIT.into(),
        action: UnitAction::Start,
        now: None,
    });
    Ok(ops)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Detection {
    pub tool: &'static str,
    pub text: String,
    pub severity: Severity,
}

/// What the two tools print when they flag something: rkhunter's
/// `Warning:` lines (with or without its `[time]` prefix) and chkrootkit's
/// `INFECTED` and `suspicious` lines. Everything else is ignored.
pub fn parse(out: &str) -> Vec<Detection> {
    let mut found: Vec<Detection> = Vec::new();
    for raw in out.lines() {
        let line = raw.trim();
        let rest = line
            .strip_prefix('[')
            .and_then(|l| l.split_once(']'))
            .map_or(line, |(_, after)| after.trim());
        let detection = if let Some(text) = rest.strip_prefix("Warning:") {
            Some(Detection {
                tool: "rkhunter",
                text: clean_line(text, 200),
                severity: Severity::Medium,
            })
        } else if line.contains("INFECTED") {
            Some(Detection {
                tool: "chkrootkit",
                text: clean_line(line, 200),
                severity: Severity::High,
            })
        } else if line.to_ascii_lowercase().contains("suspicious") || line.contains("Possible") {
            Some(Detection {
                tool: "chkrootkit",
                text: clean_line(line, 200),
                severity: Severity::Low,
            })
        } else {
            None
        };
        if let Some(d) = detection
            && !d.text.is_empty()
            && !found.iter().any(|f| f.tool == d.tool && f.text == d.text)
            && found.len() < MAX_FINDINGS
        {
            found.push(d);
        }
    }
    found
}

pub fn evaluate(sandbox: &Sandbox, at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let output = sandbox.read(OUT);
    let detections = output.as_deref().map(parse).unwrap_or_default();
    for (n, d) in detections.iter().enumerate() {
        findings.push(Finding {
            id: format!("rootkit.{}.{n}", d.tool),
            plugin: ID.into(),
            severity: d.severity,
            title_key: "rootkit-flagged-title".into(),
            summary_key: "rootkit-flagged-summary".into(),
            args: BTreeMap::from([
                ("tool".to_string(), d.tool.to_string()),
                ("text".to_string(), d.text.clone()),
            ]),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: at.into(),
        });
    }
    findings.push(note(sandbox, output.is_some(), at));
    let outcome = match (&output, detections.is_empty()) {
        (None, _) => CheckOutcome::NotAssessed,
        (Some(_), true) => CheckOutcome::Pass,
        (Some(_), false) => CheckOutcome::Fail,
    };
    CheckReport {
        results: vec![CheckResult {
            id: "rootkit.scan_clean".into(),
            // A lead to review, so it weighs little: both tools raise false
            // alarms after package updates.
            severity: Severity::Low,
            outcome,
        }],
        findings,
    }
}

/// What the machine has, and what to run to get the missing tool.
fn note(sandbox: &Sandbox, scanned: bool, at: &str) -> Finding {
    let rk = installed(sandbox, RKHUNTER).is_some();
    let ck = installed(sandbox, CHKROOTKIT).is_some();
    let mut args = BTreeMap::new();
    let case = match (rk, ck) {
        (false, false) => {
            args.insert(
                "install".into(),
                install_command(sandbox, "rkhunter")
                    .unwrap_or_else(|| "your package manager: rkhunter".into()),
            );
            "none"
        }
        (true, true) => {
            if scanned {
                "scanned"
            } else {
                "ready"
            }
        }
        (true, false) => {
            args.insert("tools".into(), "rkhunter".into());
            if scanned { "scanned" } else { "ready" }
        }
        (false, true) => {
            args.insert("tools".into(), "chkrootkit".into());
            if scanned { "scanned" } else { "ready" }
        }
    };
    detected(ID, "rootkit", case, args, None, at)
}

#[cfg(test)]
mod tests;
