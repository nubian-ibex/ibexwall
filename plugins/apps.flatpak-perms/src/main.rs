// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `apps.flatpak-perms`: which Flatpak apps can see more than a sandbox
//! should allow. Read-only. For every installed app (system and per-user)
//! the plugin takes the permissions in its `metadata` and applies the
//! administrator's and the user's overrides (a leading `!` removes one),
//! then reports the ones that reach the home folder or the whole disk, all
//! devices, the SSH and GPG agents, the full session or system bus, or the
//! sandbox's own `org.freedesktop.Flatpak` service (a way out of the
//! sandbox). App ids are untrusted and travel as arguments only.

use std::collections::{BTreeMap, BTreeSet};

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Perms)) {
        eprintln!("ibexwall-plugin-flatpak-perms: {err}");
        std::process::exit(1);
    }
}

struct Perms;

impl Plugin for Perms {
    fn id(&self) -> &'static str {
        "apps.flatpak-perms"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// `section -> key -> value` of a GLib key file.
type KeyFile = BTreeMap<String, BTreeMap<String, String>>;

fn parse(text: &str) -> KeyFile {
    let mut out = KeyFile::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
        } else if let Some((key, value)) = line.split_once('=') {
            out.entry(section.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

/// `a;b;!c;` as ordered items.
fn items(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Metadata first, then each override in order; `!x` removes `x`.
fn effective(layers: &[KeyFile], section: &str, key: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for layer in layers {
        for item in items(layer.get(section).and_then(|s| s.get(key))) {
            match item.strip_prefix('!') {
                Some(removed) => {
                    set.remove(removed);
                }
                None => {
                    set.insert(item);
                }
            }
        }
    }
    set
}

/// Bus names and their policy (`talk`, `own`, `see`, `none`), overrides
/// replacing earlier values.
fn bus_policy(layers: &[KeyFile], section: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for layer in layers {
        for (name, policy) in layer.get(section).into_iter().flatten() {
            out.insert(name.clone(), policy.clone());
        }
    }
    out
}

struct Hit {
    permission: String,
    what: &'static str,
    severity: Severity,
}

fn dangers(layers: &[KeyFile]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut add = |permission: &str, what, severity| {
        hits.push(Hit {
            permission: permission.to_string(),
            what,
            severity,
        });
    };
    let fs = effective(layers, "Context", "filesystems");
    for item in &fs {
        // `home:ro` is still the whole home folder, readable.
        let path = item.split(':').next().unwrap_or(item);
        let read_only = item.ends_with(":ro");
        match path {
            "host" | "host-os" | "host-etc" | "/" => add(
                &format!("filesystem={item}"),
                "host",
                if read_only {
                    Severity::Medium
                } else {
                    Severity::High
                },
            ),
            "home" | "~" => add(
                &format!("filesystem={item}"),
                "home",
                if read_only {
                    Severity::Low
                } else {
                    Severity::Medium
                },
            ),
            _ => {}
        }
    }
    if effective(layers, "Context", "devices").contains("all") {
        add("device=all", "devices", Severity::Medium);
    }
    let sockets = effective(layers, "Context", "sockets");
    if sockets.contains("ssh-auth") {
        add("socket=ssh-auth", "ssh", Severity::Medium);
    }
    if sockets.contains("gpg-agent") {
        add("socket=gpg-agent", "gpg", Severity::Medium);
    }
    if sockets.contains("system-bus") {
        add("socket=system-bus", "system-bus", Severity::High);
    }
    if sockets.contains("session-bus") {
        add("socket=session-bus", "session-bus", Severity::High);
    }
    // X11 without Wayland as the alternative lets the app watch other X11
    // windows; fallback-x11 only applies when Wayland is not there.
    if sockets.contains("x11") && !sockets.contains("wayland") {
        add("socket=x11", "x11", Severity::Low);
    }
    for (name, policy) in bus_policy(layers, "Session Bus Policy") {
        if name.starts_with("org.freedesktop.Flatpak") && matches!(policy.as_str(), "talk" | "own")
        {
            add(&format!("talk={name}"), "escape", Severity::High);
        }
    }
    hits
}

/// `(app id, metadata text, override texts in order)` for every app.
fn apps(sandbox: &Sandbox) -> Vec<(String, String, Vec<String>)> {
    let mut roots: Vec<(String, String)> = vec![(
        "/var/lib/flatpak".into(),
        "/var/lib/flatpak/overrides".into(),
    )];
    for user in sandbox.list("/home") {
        roots.push((
            format!("/home/{user}/.local/share/flatpak"),
            format!("/home/{user}/.local/share/flatpak/overrides"),
        ));
    }
    let mut out = Vec::new();
    for (root, overrides) in roots {
        for id in sandbox.list(&format!("{root}/app")) {
            let Some(metadata) = sandbox.read(&format!("{root}/app/{id}/current/active/metadata"))
            else {
                continue;
            };
            let mut layers = vec![];
            // Global override first, then the app's own.
            if let Some(text) = sandbox.read(&format!("{overrides}/global")) {
                layers.push(text);
            }
            if let Some(text) = sandbox.read(&format!("{overrides}/{id}")) {
                layers.push(text);
            }
            out.push((id, metadata, layers));
        }
    }
    out
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let installed = sandbox.exists("/var/lib/flatpak")
        || sandbox
            .list("/home")
            .iter()
            .any(|user| sandbox.exists(&format!("/home/{user}/.local/share/flatpak")));
    let id = "flatpak.permissions";
    if !installed {
        return CheckReport {
            results: vec![CheckResult {
                id: id.into(),
                severity: Severity::Medium,
                outcome: CheckOutcome::NotApplicable,
            }],
            findings: vec![],
        };
    }
    let mut findings = Vec::new();
    let mut worst = None::<Severity>;
    for (app, metadata, overrides) in apps(sandbox) {
        let mut layers = vec![parse(&metadata)];
        layers.extend(overrides.iter().map(|text| parse(text)));
        for hit in dangers(&layers) {
            let mut args = BTreeMap::new();
            args.insert("app".to_string(), app.clone());
            args.insert("permission".to_string(), hit.permission.clone());
            if matches!(hit.severity, Severity::High | Severity::Medium) {
                worst = Some(match worst {
                    Some(Severity::High) => Severity::High,
                    _ => hit.severity,
                });
            }
            findings.push(Finding {
                id: format!("flatpak.{app}.{}", hit.permission),
                plugin: "apps.flatpak-perms".into(),
                severity: hit.severity,
                // One message per kind of reach: Fluent cannot build a
                // sentence from a key held in an argument.
                title_key: format!("flatpak-{}-title", hit.what),
                summary_key: format!("flatpak-{}-summary", hit.what),
                args,
                references: vec![],
                remediation: None,
                status: FindingStatus::Open,
                detected_at: detected_at.into(),
            });
        }
    }
    CheckReport {
        results: vec![CheckResult {
            id: id.into(),
            severity: Severity::Medium,
            outcome: if worst.is_some() {
                CheckOutcome::Fail
            } else {
                CheckOutcome::Pass
            },
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
            "ibx-perm-{}-{}",
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

    fn meta(app: &str, text: &str) -> (String, String) {
        (
            format!("/var/lib/flatpak/app/{app}/current/active/metadata"),
            text.to_string(),
        )
    }

    fn ids(report: &CheckReport) -> Vec<String> {
        report.findings.iter().map(|f| f.id.clone()).collect()
    }

    #[test]
    fn broad_permissions_are_findings_with_the_right_weight() {
        let (path, text) = meta(
            "org.example.Wide",
            "[Context]\nshared=network;\nsockets=wayland;ssh-auth;session-bus;\ndevices=all;\nfilesystems=host;home:ro;xdg-download;\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\norg.gnome.Shell=none\n",
        );
        let (root, sandbox) = tree(&[(&path, &text)]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        let mut got = ids(&report);
        got.sort();
        assert_eq!(
            got,
            [
                "flatpak.org.example.Wide.device=all",
                "flatpak.org.example.Wide.filesystem=home:ro",
                "flatpak.org.example.Wide.filesystem=host",
                "flatpak.org.example.Wide.socket=session-bus",
                "flatpak.org.example.Wide.socket=ssh-auth",
                "flatpak.org.example.Wide.talk=org.freedesktop.Flatpak",
            ]
        );
        let sev = |id: &str| {
            report
                .findings
                .iter()
                .find(|f| f.id.ends_with(id))
                .unwrap()
                .severity
        };
        assert_eq!(sev("filesystem=host"), Severity::High);
        assert_eq!(sev("filesystem=home:ro"), Severity::Low);
        assert_eq!(sev("talk=org.freedesktop.Flatpak"), Severity::High);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_override_can_remove_a_permission_and_add_one() {
        let (path, text) = meta(
            "org.example.App",
            "[Context]\nfilesystems=host;\nsockets=wayland;\n",
        );
        let (root, sandbox) = tree(&[
            (&path, &text),
            (
                "/var/lib/flatpak/overrides/org.example.App",
                "[Context]\nfilesystems=!host;home;\n",
            ),
        ]);
        assert_eq!(
            ids(&evaluate(&sandbox, "now")),
            ["flatpak.org.example.App.filesystem=home"]
        );
        std::fs::remove_dir_all(root).unwrap();
        // A global override applies to every app.
        let (root, sandbox) = tree(&[
            (&path, &text),
            (
                "/var/lib/flatpak/overrides/global",
                "[Context]\nfilesystems=!host;\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert!(report.findings.is_empty());
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn x11_only_counts_without_wayland_and_narrow_apps_are_clean() {
        let (p1, t1) = meta(
            "a.B",
            "[Context]\nsockets=x11;fallback-x11;\nfilesystems=xdg-documents;\n",
        );
        let (p2, t2) = meta("c.D", "[Context]\nsockets=x11;wayland;\n");
        let (root, sandbox) = tree(&[(&p1, &t1), (&p2, &t2)]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(ids(&report), ["flatpak.a.B.socket=x11"]);
        // Low findings alone do not fail the check.
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn per_user_installs_are_read_and_no_flatpak_is_not_applicable() {
        let (root, sandbox) = tree(&[(
            "/home/ana/.local/share/flatpak/app/o.P/current/active/metadata",
            "[Context]\ndevices=all;\n",
        )]);
        assert_eq!(ids(&evaluate(&sandbox, "now")), ["flatpak.o.P.device=all"]);
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
