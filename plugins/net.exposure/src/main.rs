// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.exposure`: which TCP ports answer on this computer's own addresses,
//! found with nmap. The targets are never taken from the caller: the plan
//! reads the machine's own IPv4 addresses from `/proc/net/fib_trie` and
//! builds the command from those alone, so this cannot be pointed at another
//! host. It reports what listens, to compare with what you expect; seen from
//! the machine itself it does not show what a firewall blocks from outside.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckReport, Finding, FindingStatus, Op, Severity, UnitAction};
use ibexwall_sdk::detect::{detected, install_command};
use ibexwall_sdk::scanner::{Service, clean_line, schedule, service_unit, timer_unit};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const ID: &str = "net.exposure";
const NMAP: &str = "/usr/bin/nmap";
const SERVICE_UNIT: &str = "ibexwall-exposure-scan.service";
const TIMER_UNIT: &str = "ibexwall-exposure-scan.timer";
const SERVICE_FILE: &str = "/etc/systemd/system/ibexwall-exposure-scan.service";
const TIMER_FILE: &str = "/etc/systemd/system/ibexwall-exposure-scan.timer";
const MANAGED: &str = "/var/lib/ibexwall/exposure/.managed";
const XML: &str = "/var/lib/ibexwall/exposure/nmap.xml";
const MAX_TARGETS: usize = 8;
const MAX_FINDINGS: usize = 30;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `scan` or `schedule`. There is no target to give.
    pub action: String,
    pub every: String,
}

struct Exposure;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Exposure)) {
        eprintln!("ibexwall-plugin-exposure: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Exposure {
    fn id(&self) -> &'static str {
        ID
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![],
            findings: evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"),
        })
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

/// This machine's own IPv4 addresses: the `/32 host LOCAL` entries of the
/// kernel's routing table.
pub fn local_addresses(fib_trie: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut previous: Option<&str> = None;
    for line in fib_trie.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("/32 host LOCAL")
            && let Some(addr) = previous
            && addr.parse::<std::net::Ipv4Addr>().is_ok()
            && !out.iter().any(|a| a == addr)
        {
            out.push(addr.to_string());
        }
        previous = trimmed.strip_prefix("|-- ");
    }
    out
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
    if !sandbox.exists(NMAP) {
        return Err(PluginError::invalid(
            "action",
            "nmap is not installed; IbexWall installs no software",
        ));
    }
    let targets = local_addresses(&sandbox.read("/proc/net/fib_trie").unwrap_or_default());
    if targets.is_empty() {
        return Err(PluginError::invalid(
            "action",
            "this computer's addresses could not be read",
        ));
    }
    if targets.len() > MAX_TARGETS {
        return Err(PluginError::invalid(
            "action",
            "too many local addresses to scan",
        ));
    }
    let commands = vec![format!(
        "-{NMAP} -sT -Pn -n --open -p- -T4 -oX - {}",
        targets.join(" ")
    )];
    // nmap writes its XML to standard output and systemd puts that in the
    // state directory: on Fedora nmap runs in an SELinux domain that may not
    // open files there itself.
    let unit = service_unit(&Service {
        plugin: ID,
        description: "IbexWall open-ports scan of this computer",
        state_dir: "ibexwall/exposure",
        writable: &[],
        commands: &commands,
        timeout: "30min",
        host_view: false,
        // nmap runs in its own SELinux domain on Fedora, and the transition is
        // refused under NoNewPrivileges. The unit is still a read-only system
        // with no writable path but its own state directory.
        no_new_privileges: false,
    })
    .replace(
        "Type=oneshot\n",
        &format!("Type=oneshot\nStandardOutput=truncate:{XML}\n"),
    );
    let file = |path: &str, content: String| Op::FileWrite {
        path: path.into(),
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![
        file(MANAGED, "# Managed by IbexWall (net.exposure).\n".into()),
        file(SERVICE_FILE, unit),
    ];
    if timer {
        ops.push(file(
            TIMER_FILE,
            timer_unit(ID, "IbexWall open-ports scan", every),
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
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    /// Non-loopback addresses it answers on.
    pub addresses: Vec<String>,
}

fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')?;
    Some(&tag[start..start + end])
}

/// The open TCP ports on addresses other than loopback, from nmap's XML,
/// grouped by port. Loopback is skipped: a service only on 127.0.0.1 is not
/// reachable from the network.
pub fn parse(xml: &str) -> Vec<OpenPort> {
    let mut by_port: BTreeMap<u16, OpenPort> = BTreeMap::new();
    // `<host ` only: nmap also writes `<hosthint>`, `<hostnames>` and
    // `<hostscript>`, which are not hosts.
    let xml = xml.replace("<host>", "<host >");
    for host in xml.split("<host ").skip(1) {
        let host = host.split("</host>").next().unwrap_or("");
        let Some(addr) = host
            .split("<address ")
            .nth(1)
            .and_then(|t| attribute(t, "addr"))
        else {
            continue;
        };
        if addr.starts_with("127.") || addr == "::1" {
            continue;
        }
        for port in host.split("<port ").skip(1) {
            let port = port.split("</port>").next().unwrap_or("");
            let head = port.split('>').next().unwrap_or("");
            if attribute(head, "protocol") != Some("tcp") || !port.contains("state=\"open\"") {
                continue;
            }
            let Some(number) = attribute(head, "portid").and_then(|p| p.parse::<u16>().ok()) else {
                continue;
            };
            let service = port
                .split("<service ")
                .nth(1)
                .and_then(|t| attribute(t, "name"))
                .map_or("unknown".to_string(), |n| clean_line(n, 40));
            let entry = by_port.entry(number).or_insert_with(|| OpenPort {
                port: number,
                service,
                addresses: vec![],
            });
            let addr = clean_line(addr, 45);
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }
    }
    by_port.into_values().take(MAX_FINDINGS).collect()
}

pub fn evaluate(sandbox: &Sandbox, at: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let xml = sandbox.read(XML);
    for open in xml.as_deref().map(parse).unwrap_or_default() {
        findings.push(Finding {
            id: format!("exposure.tcp.{}", open.port),
            plugin: ID.into(),
            severity: Severity::Info,
            title_key: "exposure-open-title".into(),
            summary_key: "exposure-open-summary".into(),
            args: BTreeMap::from([
                ("port".to_string(), open.port.to_string()),
                ("service".to_string(), open.service),
                ("addresses".to_string(), open.addresses.join(", ")),
            ]),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: at.into(),
        });
    }
    let mut args = BTreeMap::new();
    let case = if !sandbox.exists(NMAP) {
        args.insert(
            "install".into(),
            install_command(sandbox, "nmap").unwrap_or_else(|| "your package manager: nmap".into()),
        );
        "none"
    } else if xml.is_some() {
        "scanned"
    } else {
        "ready"
    };
    findings.push(detected(ID, "exposure", case, args, None, at));
    findings
}

#[cfg(test)]
mod tests;
