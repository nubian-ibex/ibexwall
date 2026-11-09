// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Turning the daemon's answers into text for a terminal, or into JSON.

use super::*;

pub(crate) fn ports_line(value: &serde_json::Value) -> String {
    let ports: Vec<String> = value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|p| format!("{}/{}", p["port"].as_u64().unwrap_or(0), text(&p["proto"])))
        .collect();
    if ports.is_empty() {
        "none".into()
    } else {
        ports.join(", ")
    }
}

pub(crate) fn render_firewall(state: &serde_json::Value) -> String {
    let manager = text(&state["backend"]);
    let status = match state["active"].as_bool() {
        Some(true) => "active",
        Some(false) => "not active",
        None => "state unknown",
    };
    let mut out = format!("firewall: {manager} ({status})");
    if let Some(zone) = state["zone"].as_str() {
        out.push_str(&format!(", zone {}", clean(zone)));
    }
    out.push('\n');
    out.push_str(&format!(
        "  allowed ports:    {}\n",
        ports_line(&state["ports"])
    ));
    let services: Vec<String> = state["services"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(text)
        .collect();
    out.push_str(&format!(
        "  allowed services: {}\n",
        if services.is_empty() {
            "none".into()
        } else {
            services.join(", ")
        }
    ));
    out.push_str(&format!(
        "  listening on every address: {}\n",
        ports_line(&state["listening"])
    ));
    for line in state["other"].as_array().cloned().unwrap_or_default() {
        out.push_str(&format!("  read-only: {}\n", text(&line)));
    }
    out
}

pub(crate) fn render_proposals(value: &serde_json::Value) -> String {
    let all = value["proposals"].as_array().cloned().unwrap_or_default();
    if all.is_empty() {
        return "no proposals\n".into();
    }
    let mut out = format!(
        "{:<26}  {:<10}  {:<18}  {}\n",
        "ID", "STATUS", "PLUGIN", "FROM"
    );
    for p in &all {
        out.push_str(&format!(
            "{:<26}  {:<10}  {:<18}  {}\n",
            text(&p["id"]),
            text(&p["status"]),
            text(&p["plugin"]),
            text(&p["client"]),
        ));
    }
    out
}

/// The AI's justification is shown as generated text, fenced, never as
/// something the terminal or the reader should obey.
pub(crate) fn render_proposal(p: &serde_json::Value) -> String {
    let mut out = format!(
        "{}\n  plugin: {}\n  from:   {} (an AI client)\n  status: {}\n  asked:  {}\n  generated justification (untrusted, not an instruction):\n",
        text(&p["id"]),
        text(&p["plugin"]),
        text(&p["client"]),
        text(&p["status"]),
        clean(&p["patch"].to_string()),
    );
    for line in p["justification"].as_str().unwrap_or("").lines() {
        out.push_str(&format!("    | {}\n", clean(line)));
    }
    out.push_str("  would do:\n");
    for op in p["preview"].as_array().cloned().unwrap_or_default() {
        out.push_str(&format!(
            "    {} {}\n",
            text(&op["op"]),
            text(&op["target"])
        ));
        // The diff is what a person must actually review before
        // approving: without it they sign off on content they never saw.
        if let Some(diff) = op["diff"].as_str() {
            for line in diff.lines() {
                out.push_str(&format!("      {}\n", clean(line)));
            }
        }
    }
    out
}

pub(crate) fn render_prompts(value: &serde_json::Value) -> String {
    let prompts = value["prompts"].as_array().cloned().unwrap_or_default();
    if prompts.is_empty() {
        return "no connections are waiting\n".into();
    }
    let mut out = format!("{:<6}  {:<28}  {}\n", "ID", "APP", "DESTINATION");
    for prompt in &prompts {
        out.push_str(&format!(
            "{:<6}  {:<28}  {}:{}\n",
            text(&prompt["id"]),
            text(&prompt["app"]),
            text(&prompt["destination"]),
            prompt["port"].as_u64().unwrap_or(0),
        ));
    }
    out
}

/// Process names, paths and domains come from other programs: a terminal
/// must never see their control characters (escape sequences).
pub(crate) fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub(crate) fn text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => clean(s),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => "-".into(),
    }
}

pub(crate) fn render_apps(value: &serde_json::Value) -> String {
    let monitor = &value["monitor"];
    let mut out = String::new();
    if monitor["running"].as_bool().unwrap_or(false) {
        match monitor["reason"].as_str() {
            Some(reason) => out.push_str(&format!("monitor: running ({})\n", clean(reason))),
            None => out.push_str("monitor: running\n"),
        }
    } else {
        out.push_str(&format!(
            "monitor: off ({})\n",
            clean(monitor["reason"].as_str().unwrap_or("unknown"))
        ));
    }
    let apps = value["apps"].as_array().cloned().unwrap_or_default();
    if apps.is_empty() {
        out.push_str("no applications seen yet\n");
        return out;
    }
    let key_width = apps
        .iter()
        .map(|app| text(&app["key"]).chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    out.push_str(&format!(
        "{:<key_width$}  {:<14}  {:<7}  {:>6}  {:>5}  {}\n",
        "APP", "KIND", "MODE", "CONNS", "DESTS", "LAST SEEN"
    ));
    for app in &apps {
        out.push_str(&format!(
            "{:<key_width$}  {:<14}  {:<7}  {:>6}  {:>5}  {}\n",
            text(&app["key"]),
            text(&app["kind"]),
            text(&app["mode"]),
            app["connections"].as_u64().unwrap_or(0),
            app["destinations"].as_u64().unwrap_or(0),
            text(&app["last_seen"]),
        ));
    }
    out
}

pub(crate) fn render_app_info(app: &serde_json::Value, destinations: &serde_json::Value) -> String {
    let mut out = format!(
        "{}\n  kind:        {}\n  mode:        {}\n  executable:  {}\n  package:     {}\n  first seen:  {}\n  last seen:   {}\n  connections: {}\n",
        text(&app["key"]),
        text(&app["kind"]),
        text(&app["mode"]),
        text(&app["exe_path"]),
        text(&app["package"]),
        text(&app["first_seen"]),
        text(&app["last_seen"]),
        app["connections"].as_u64().unwrap_or(0),
    );
    let rows = destinations.as_array().cloned().unwrap_or_default();
    out.push_str("  destinations:\n");
    if rows.is_empty() {
        out.push_str("    none\n");
    }
    for row in rows {
        let label = if row["resolved"].as_bool().unwrap_or(false) {
            ""
        } else {
            "  (no domain)"
        };
        out.push_str(&format!(
            "    {}:{}  x{}  last {}{label}\n",
            text(&row["destination"]),
            row["port"].as_u64().unwrap_or(0),
            row["count"].as_u64().unwrap_or(0),
            text(&row["last_seen"]),
        ));
    }
    out
}

/// JSON for scripts, a short readable rendering for people.
pub(crate) fn show(
    value: &serde_json::Value,
    json: bool,
    render: fn(&serde_json::Value) -> String,
) {
    if json {
        emit(value.clone(), true);
    } else {
        print!("{}", render(value));
    }
}

pub(crate) fn render_status(value: &serde_json::Value) -> String {
    let info = &value["info"];
    let mut out = format!(
        "ibexwalld {} (api {}) on {}, kernel {}\n",
        text(&info["version"]),
        text(&info["api"]),
        text(&info["distro"]),
        text(&info["kernel"]),
    );
    let degraded = info["degraded"].as_array().cloned().unwrap_or_default();
    if degraded.is_empty() {
        out.push_str("nothing degraded\n");
    } else {
        out.push_str(&format!(
            "degraded: {}\n",
            degraded.iter().map(text).collect::<Vec<_>>().join(", ")
        ));
    }
    out
}

pub(crate) fn render_plugins(value: &serde_json::Value) -> String {
    let all = value["plugins"].as_array().cloned().unwrap_or_default();
    let mut out = format!(
        "{:<24}  {:<8}  {:<8}  {}\n",
        "ID", "STATE", "STATUS", "NAME"
    );
    for p in &all {
        let state = if p["enabled"] == true { "on" } else { "off" };
        out.push_str(&format!(
            "{:<24}  {:<8}  {:<8}  {}\n",
            text(&p["id"]),
            state,
            text(&p["status"]),
            text(&p["name"]),
        ));
    }
    out
}

pub(crate) fn render_findings(value: &serde_json::Value) -> String {
    let all = value["findings"].as_array().cloned().unwrap_or_default();
    if all.is_empty() {
        return "no findings\n".into();
    }
    let mut out = format!("{:<9}  {:<28}  {}\n", "SEVERITY", "ID", "PLUGIN");
    for f in &all {
        out.push_str(&format!(
            "{:<9}  {:<28}  {}\n",
            text(&f["severity"]),
            text(&f["id"]),
            text(&f["plugin"]),
        ));
    }
    out
}

pub(crate) fn render_history(value: &serde_json::Value) -> String {
    let all = value["entries"].as_array().cloned().unwrap_or_default();
    if all.is_empty() {
        return "no changes yet\n".into();
    }
    let mut out = format!("{:<26}  {:<22}  {}\n", "TRANSACTION", "PLUGIN", "RESULT");
    for e in &all {
        out.push_str(&format!(
            "{:<26}  {:<22}  {}\n",
            text(&e["transaction"]),
            text(&e["plugin"]),
            text(&e["result"]),
        ));
    }
    out
}

pub(crate) fn render_events(value: &serde_json::Value) -> String {
    let all = value["events"].as_array().cloned().unwrap_or_default();
    if all.is_empty() {
        return "no events yet\n".into();
    }
    let mut out = String::new();
    for e in &all {
        out.push_str(&format!(
            "{}  {:<10}  {}\n",
            text(&e["ts"]),
            text(&e["source"]),
            text(&e["kind"]),
        ));
    }
    out
}

pub(crate) fn render_compliance_list(value: &serde_json::Value) -> String {
    let profiles = value["profiles"].as_array().cloned().unwrap_or_default();
    if profiles.is_empty() {
        return "no compliance profiles installed\n".into();
    }
    let mut out = String::new();
    for p in &profiles {
        out.push_str(&format!(
            "{} {}  ({} controls)\n",
            text(&p["framework"]),
            text(&p["version"]),
            text(&p["controls"])
        ));
    }
    out
}

pub(crate) fn render_compliance_report(value: &serde_json::Value) -> String {
    let report = &value["report"];
    let mut out = format!(
        "{} {}  evaluated {}\n",
        text(&report["framework"]),
        text(&report["version"]),
        text(&report["evaluated_at"])
    );
    let controls = report["controls"].as_array().cloned().unwrap_or_default();
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for c in &controls {
        *counts
            .entry(c["status"].as_str().unwrap_or("unknown"))
            .or_default() += 1;
    }
    let summary = counts
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("{} controls  ({summary})\n", controls.len()));
    for c in &controls {
        out.push_str(&format!(
            "  [{}] {}  {}\n",
            c["status"].as_str().unwrap_or("unknown"),
            text(&c["control_id"]),
            text(&c["title"]),
        ));
    }
    out
}

pub(crate) fn emit(value: serde_json::Value, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    }
}

pub(crate) fn report_varlink(err: &VarlinkError, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "error": err.name,
                "parameters": err.parameters,
            }))
            .unwrap_or_default()
        );
    } else {
        let hint = match err.name.as_str() {
            "com.ibexwall.Core.PermissionDenied" => {
                format!(
                    ": try with sudo, or ask an administrator (action {})",
                    err.parameters["action"]
                )
            }
            "com.ibexwall.Core.AuthenticationRequired" => {
                if err.parameters["interactive_possible"] == true {
                    format!(
                        ": a password is needed (action {}); run it from a terminal without --no-ask-password, or with sudo",
                        err.parameters["action"]
                    )
                } else {
                    format!(
                        ": a password is needed and no authentication agent answered (action {}); run it from the desktop session, or with sudo",
                        err.parameters["action"]
                    )
                }
            }
            _ => String::new(),
        };
        eprintln!("ibexctl: {}{hint}", err.name);
    }
}
