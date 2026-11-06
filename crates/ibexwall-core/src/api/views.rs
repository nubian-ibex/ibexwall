// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only views of the core, shaped for the varlink replies.

use super::*;

pub(crate) fn info(_core: &Arc<Core>) -> Value {
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("ID=").map(str::to_string))
        })
        .unwrap_or_else(|| "unknown".into());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    json!({
        "info": {
            "version": env!("CARGO_PKG_VERSION"),
            "api": 1,
            "distro": distro,
            "kernel": kernel,
            "features": [],
            "degraded": [],
        }
    })
}

/// The resolver's published counters; counts only, never query names.
pub(crate) fn dns_status(core: &Arc<Core>) -> Value {
    // `dns_status_file` is already rooted for the sandbox, while the fs
    // translates under its own root; strip once so the two never double
    // up (the resolver itself writes the rooted path).
    let path = crate::engine::under_root(&ibexwall_proto::names::dns_status_file());
    let status: Value = core
        .engine
        .sys
        .fs
        .read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| {
            json!({
                "running": false,
                "updated_at": String::new(),
                "forwarded": 0,
                "blocked_list": 0,
                "blocked_canary": 0,
                "blocked_doh": 0,
                "upstream_errors": 0,
            })
        });
    json!({ "dns_status": status })
}

pub(crate) fn posture(core: &Arc<Core>) -> Value {
    let results = core.state.list_check_results().unwrap_or_default();
    let open_findings = core
        .state
        .list_findings(None)
        .unwrap_or_default()
        .iter()
        .filter(|f| f.get("status").and_then(Value::as_str) == Some("open"))
        .count();
    let protections: Vec<Value> = core
        .plugins
        .plugins()
        .map(|entry| {
            json!({
                "plugin": entry.manifest.id,
                "state": if core.state.plugin_enabled(&entry.manifest.id).unwrap_or(false) { "on" } else { "off" },
                "summary_key": format!("plugin-{}-summary", entry.manifest.id),
            })
        })
        .collect();
    json!({
        "posture": {
            "score": ibexwall_proto::posture_score(&results),
            "generated_at": ibexwall_sys::RealClock.rfc3339_now(),
            "protections": protections,
            "open_findings": open_findings,
            "results": results,
        }
    })
}

pub(crate) fn list_plugins(core: &Arc<Core>) -> Vec<PluginInfo> {
    core.plugins
        .plugins()
        .map(|entry| PluginInfo {
            id: entry.manifest.id.clone(),
            name: entry
                .manifest
                .name
                .get(names::LOCALE_SOURCE)
                .cloned()
                .unwrap_or_default(),
            names: entry.manifest.name.clone(),
            version: entry.manifest.version.clone(),
            kinds: entry
                .manifest
                .kinds
                .iter()
                .map(|k| format!("{k:?}").to_lowercase())
                .collect(),
            enabled: core
                .state
                .plugin_enabled(&entry.manifest.id)
                .unwrap_or(false),
            origin: entry.manifest.origin,
            status: "ok".into(),
            compatible: true,
            conflicts: entry.manifest.conflicts.units.clone(),
            locked: false,
        })
        .collect()
}
