// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.openscap`: the machine against a SCAP security profile (ANSSI,
//! CIS, STIG and others), using the distribution's own SCAP Security Guide
//! content. The plan writes a oneshot unit that runs `oscap xccdf eval` and
//! leaves the XCCDF results in IbexWall's state directory; the check lists the
//! rules that failed, worst first. Nothing is changed on the machine, and
//! IbexWall installs neither OpenSCAP nor its content.
//!
//! The profile is named by the caller but must exist in the content file, and
//! the content file is chosen from the distribution, never from a free path.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction,
};
use ibexwall_sdk::detect::{detected, install_command};
use ibexwall_sdk::scanner::{Service, clean_line, schedule, service_unit, timer_unit};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const ID: &str = "system.openscap";
const OSCAP: &str = "/usr/bin/oscap";
const CONTENT_DIR: &str = "/usr/share/xml/scap/ssg/content";
const SERVICE_UNIT: &str = "ibexwall-openscap-scan.service";
const TIMER_UNIT: &str = "ibexwall-openscap-scan.timer";
const SERVICE_FILE: &str = "/etc/systemd/system/ibexwall-openscap-scan.service";
const TIMER_FILE: &str = "/etc/systemd/system/ibexwall-openscap-scan.timer";
const MANAGED: &str = "/var/lib/ibexwall/openscap/.managed";
const RESULTS: &str = "/var/lib/ibexwall/openscap/results.xml";
const PROFILE_PREFIX: &str = "xccdf_org.ssgproject.content_profile_";
const MAX_FINDINGS: usize = 25;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `scan` or `schedule`.
    pub action: String,
    /// The profile's short name, such as `standard` or `anssi_bp28_minimal`.
    /// Defaults to `standard`.
    pub profile: String,
    pub every: String,
}

struct Openscap;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Openscap)) {
        eprintln!("ibexwall-plugin-openscap: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Openscap {
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

fn os_field(sandbox: &Sandbox, name: &str) -> String {
    sandbox
        .read("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .map(|v| v.trim_matches('"').to_ascii_lowercase())
        .unwrap_or_default()
}

/// The SCAP Security Guide data stream for this distribution, when it is
/// installed: `ssg-fedora-ds.xml`, `ssg-ubuntu2404-ds.xml`, `ssg-debian12-ds.xml`.
pub fn content_file(sandbox: &Sandbox) -> Option<String> {
    let version = os_field(sandbox, "VERSION_ID");
    let name = match os_field(sandbox, "ID").as_str() {
        "fedora" => "ssg-fedora-ds.xml".to_string(),
        "ubuntu" => format!("ssg-ubuntu{}-ds.xml", version.replace('.', "")),
        "debian" => format!(
            "ssg-debian{}-ds.xml",
            version.split('.').next().unwrap_or("")
        ),
        _ => return None,
    };
    sandbox
        .exists(&format!("{CONTENT_DIR}/{name}"))
        .then_some(name)
}

fn profile_ok(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 60
        && profile
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
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
    let profile = if config.profile.is_empty() {
        "standard"
    } else {
        config.profile.as_str()
    };
    if !profile_ok(profile) {
        return Err(PluginError::invalid(
            "profile",
            "lowercase letters, digits and `_`",
        ));
    }
    if !sandbox.exists(OSCAP) {
        return Err(PluginError::invalid(
            "action",
            "OpenSCAP is not installed; IbexWall installs no software",
        ));
    }
    let content = content_file(sandbox).ok_or_else(|| {
        PluginError::invalid(
            "action",
            "the SCAP Security Guide content for this distribution is not installed; IbexWall installs no software",
        )
    })?;
    let path = format!("{CONTENT_DIR}/{content}");
    if !sandbox
        .read(&path)
        .is_some_and(|text| text.contains(&format!("{PROFILE_PREFIX}{profile}\"")))
    {
        return Err(PluginError::invalid(
            "profile",
            format!("`{profile}` is not a profile of {content}"),
        ));
    }
    let commands = vec![format!(
        "-{OSCAP} xccdf eval --profile {PROFILE_PREFIX}{profile} --results {RESULTS} {path}"
    )];
    let unit = service_unit(&Service {
        plugin: ID,
        description: "IbexWall security profile check",
        state_dir: "ibexwall/openscap",
        writable: &[],
        commands: &commands,
        timeout: "60min",
        host_view: false,
        no_new_privileges: true,
    });
    let file = |path: &str, content: String| Op::FileWrite {
        path: path.into(),
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![
        file(MANAGED, "# Managed by IbexWall (system.openscap).\n".into()),
        file(SERVICE_FILE, unit),
    ];
    if timer {
        ops.push(file(
            TIMER_FILE,
            timer_unit(ID, "IbexWall security profile check", every),
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub profile: String,
    pub passed: usize,
    pub failed: usize,
    pub other: usize,
    /// Failed rules, worst first: `(short id, severity)`.
    pub failures: Vec<(String, Severity)>,
}

fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')?;
    Some(&tag[start..start + end])
}

fn severity(name: &str) -> Severity {
    match name {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// The counts and the failed rules from an XCCDF results file.
pub fn parse(xml: &str) -> Outcome {
    let mut out = Outcome::default();
    if let Some(tag) = xml.split("<profile ").nth(1) {
        let head = tag.split('>').next().unwrap_or("");
        out.profile = attribute(head, "idref")
            .and_then(|p| p.strip_prefix(PROFILE_PREFIX))
            .map(|p| clean_line(p, 60))
            .unwrap_or_default();
    }
    for block in xml.split("<rule-result ").skip(1) {
        let block = block.split("</rule-result>").next().unwrap_or("");
        let head = block.split('>').next().unwrap_or("");
        let result = block
            .split("<result>")
            .nth(1)
            .and_then(|r| r.split("</result>").next())
            .unwrap_or("")
            .trim();
        match result {
            "pass" => out.passed += 1,
            "fail" => {
                out.failed += 1;
                let id = attribute(head, "idref")
                    .map(|i| {
                        i.strip_prefix("xccdf_org.ssgproject.content_rule_")
                            .unwrap_or(i)
                    })
                    .map(|i| clean_line(i, 100))
                    .unwrap_or_default();
                if !id.is_empty() {
                    out.failures
                        .push((id, severity(attribute(head, "severity").unwrap_or(""))));
                }
            }
            "notapplicable" | "notchecked" | "notselected" | "informational" | "" => {}
            _ => out.other += 1,
        }
    }
    // Worst first, then by name.
    let rank = |s: &Severity| match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    };
    out.failures
        .sort_by(|(ia, sa), (ib, sb)| rank(sa).cmp(&rank(sb)).then_with(|| ia.cmp(ib)));
    out
}

pub fn evaluate(sandbox: &Sandbox, at: &str) -> CheckReport {
    let xml = sandbox.read(RESULTS);
    let outcome = xml.as_deref().map(parse);
    let mut findings = Vec::new();
    if let Some(o) = &outcome {
        for (rule, severity) in o.failures.iter().take(MAX_FINDINGS) {
            findings.push(Finding {
                id: format!("openscap.{rule}"),
                plugin: ID.into(),
                severity: *severity,
                title_key: "openscap-failed-title".into(),
                summary_key: "openscap-failed-summary".into(),
                args: BTreeMap::from([
                    ("rule".to_string(), rule.clone()),
                    ("profile".to_string(), o.profile.clone()),
                ]),
                references: vec![],
                remediation: None,
                status: FindingStatus::Open,
                detected_at: at.into(),
            });
        }
    }
    findings.push(note(sandbox, outcome.as_ref(), at));
    let result = match &outcome {
        None => CheckOutcome::NotAssessed,
        Some(o) if o.passed + o.failed == 0 => CheckOutcome::NotAssessed,
        Some(o) if o.failed == 0 => CheckOutcome::Pass,
        Some(_) => CheckOutcome::Fail,
    };
    CheckReport {
        results: vec![CheckResult {
            id: "openscap.profile_passes".into(),
            // A profile is a long list of choices; it weighs as a hint.
            severity: Severity::Low,
            outcome: result,
        }],
        findings,
    }
}

fn note(sandbox: &Sandbox, outcome: Option<&Outcome>, at: &str) -> Finding {
    let mut args = BTreeMap::new();
    let case = if !sandbox.exists(OSCAP) {
        let package =
            if os_field(sandbox, "ID") == "arch" || os_field(sandbox, "ID_LIKE").contains("arch") {
                "openscap"
            } else {
                "openscap-scanner"
            };
        args.insert(
            "install".into(),
            install_command(sandbox, package)
                .unwrap_or_else(|| format!("your package manager: {package}")),
        );
        "none"
    } else if content_file(sandbox).is_none() {
        "no-content"
    } else if let Some(o) = outcome {
        args.insert("passed".into(), o.passed.to_string());
        args.insert("failed".into(), o.failed.to_string());
        args.insert("profile".into(), o.profile.clone());
        "scanned"
    } else {
        "ready"
    };
    detected(ID, "openscap", case, args, None, at)
}

#[cfg(test)]
mod tests;
