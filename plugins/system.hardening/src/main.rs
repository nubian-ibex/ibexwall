// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.hardening`: reads the hardening catalog (`catalog/hardening.json`,
//! the one the interface shows) and says, item by item, whether the machine
//! already has it. It changes nothing and proposes nothing: an item is
//! applied through the plugin that owns it, by the same reviewed change as
//! any other. The answer is one information finding with three lists.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckReport, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const CATALOG: &str = include_str!("../../../catalog/hardening.json");

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub version: u32,
    pub items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
pub struct Item {
    pub id: String,
    pub area: String,
    pub risk: String,
    pub recommended: bool,
    pub title: Text,
    pub summary: Text,
    pub breaks: Option<Text>,
    pub sources: Vec<Source>,
    pub probe: Probe,
    pub apply: Apply,
    pub doc: String,
}

#[derive(Debug, Deserialize)]
pub struct Text {
    pub en: String,
    #[serde(rename = "pt-BR")]
    pub pt_br: String,
}

#[derive(Debug, Deserialize)]
pub struct Source {
    pub name: String,
    pub url: String,
    pub section: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyWant {
    pub key: String,
    pub want: String,
    pub at_least: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Probe {
    /// Every key holds the wanted value, or a stricter one where `at_least`.
    Sysctl { keys: Vec<KeyWant> },
    /// Every module of the group is kept from loading.
    Modules { group: String },
    /// The path is a mount point with the option.
    MountOption { path: String, option: String },
}

#[derive(Debug, Deserialize)]
pub struct Apply {
    pub plugin: String,
    pub patch: Value,
}

pub fn catalog() -> Catalog {
    serde_json::from_str(CATALOG).expect("catalog/hardening.json is valid (a test checks it)")
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Applied,
    Open,
    Unknown,
}

fn meets(want: &KeyWant, live: &str) -> bool {
    live == want.want
        || (want.at_least
            && matches!(
                (live.parse::<i64>(), want.want.parse::<i64>()),
                (Ok(now), Ok(wanted)) if now >= wanted
            ))
}

fn module_files(sandbox: &Sandbox) -> Vec<String> {
    let mut texts = Vec::new();
    for dir in ["/etc/modprobe.d", "/usr/lib/modprobe.d"] {
        for name in sandbox.list(dir) {
            if name.ends_with(".conf")
                && let Some(text) = sandbox.read(&format!("{dir}/{name}"))
            {
                texts.push(text);
            }
        }
    }
    texts
}

/// `install <module> /bin/false` (or `/bin/true`) in any modprobe.d file.
fn blocked(texts: &[String], module: &str) -> bool {
    texts
        .iter()
        .flat_map(|t| t.lines())
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| {
            let mut words = l.split_whitespace();
            words.next() == Some("install")
                && words
                    .next()
                    .is_some_and(|m| m.replace('-', "_") == module.replace('-', "_"))
                && words
                    .next()
                    .is_some_and(|c| c == "/bin/false" || c == "/bin/true")
        })
}

pub fn status(sandbox: &Sandbox, probe: &Probe) -> Status {
    match probe {
        Probe::Sysctl { keys } => {
            let mut all = true;
            for want in keys {
                let path = format!("/proc/sys/{}", want.key.replace('.', "/"));
                let Some(live) = sandbox.read(&path) else {
                    return Status::Unknown;
                };
                all &= meets(want, live.trim());
            }
            if all { Status::Applied } else { Status::Open }
        }
        Probe::Modules { group } => {
            let Some(g) = ibexwall_plugin_modules::GROUPS
                .iter()
                .find(|g| g.id == group)
            else {
                return Status::Unknown;
            };
            let texts = module_files(sandbox);
            if g.modules.iter().all(|m| blocked(&texts, m)) {
                Status::Applied
            } else {
                Status::Open
            }
        }
        Probe::MountOption { path, option } => {
            let Some(mounts) = sandbox.read("/proc/mounts") else {
                return Status::Unknown;
            };
            let found = mounts.lines().rev().find_map(|l| {
                let mut f = l.split_whitespace();
                let (_, point, _, options) = (f.next()?, f.next()?, f.next()?, f.next()?);
                (point == path).then(|| options.split(',').any(|o| o == option))
            });
            if found == Some(true) {
                Status::Applied
            } else {
                Status::Open
            }
        }
    }
}

pub fn evaluate(sandbox: &Sandbox, at: &str) -> Finding {
    let catalog = catalog();
    let (mut applied, mut open, mut unknown) = (vec![], vec![], vec![]);
    for item in &catalog.items {
        match status(sandbox, &item.probe) {
            Status::Applied => applied.push(item.id.clone()),
            Status::Open => open.push(item.id.clone()),
            Status::Unknown => unknown.push(item.id.clone()),
        }
    }
    let args = BTreeMap::from([
        ("applied".to_string(), applied.join(",")),
        ("open".to_string(), open.join(",")),
        ("unknown".to_string(), unknown.join(",")),
        ("applied_count".to_string(), applied.len().to_string()),
        ("total".to_string(), catalog.items.len().to_string()),
    ]);
    Finding {
        id: "hardening.state".into(),
        plugin: "system.hardening".into(),
        severity: Severity::Info,
        title_key: "hardening-state-title".into(),
        summary_key: "hardening-state-summary".into(),
        args,
        references: vec![],
        remediation: None,
        status: FindingStatus::Open,
        detected_at: at.into(),
    }
}

struct Hardening;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Hardening)) {
        eprintln!("ibexwall-plugin-hardening: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Hardening {
    fn id(&self) -> &'static str {
        "system.hardening"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![],
            findings: vec![evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z")],
        })
    }
}

#[cfg(test)]
mod tests;
