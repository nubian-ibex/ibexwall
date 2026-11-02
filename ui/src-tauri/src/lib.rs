// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall desktop shell. The Rust side is a thin varlink client: the UI
//! logic lives in the web frontend and talks to these typed commands.
//! No remote content, no updater (updates come from the distro).

use ibexwall_proto::names;
use serde_json::{Value, json};

/// Calls one Core method and returns its `parameters` object.
async fn core(method: &str, parameters: Value) -> Result<Value, String> {
    let socket = names::core_socket();
    let mut client = ibexwall_varlink::Client::connect(&socket)
        .await
        .map_err(|e| format!("unreachable: {e}"))?;
    client
        .call(&format!("com.ibexwall.Core.{method}"), parameters)
        .await
        .map_err(|e| json!({ "code": e.name, "parameters": e.parameters }).to_string())
        .and_then(|value| serde_json::from_value(value).map_err(|e| format!("bad reply: {e}")))
}

fn err_text(error: &str) -> Value {
    // The frontend TransportError expects { code, parameters } or a bare
    // string for transport failures.
    serde_json::from_str(error).unwrap_or(json!({ "code": "unreachable", "parameters": {} }))
}

macro_rules! command {
    ($name:ident, $method:expr) => {
        #[tauri::command]
        async fn $name() -> Result<Value, Value> {
            core($method, json!({})).await.map_err(|e| err_text(&e))
        }
    };
}

command!(get_info, "GetInfo");
command!(get_posture, "GetPosture");
command!(list_plugins, "ListPlugins");
command!(list_findings, "ListFindings");
command!(run_checks, "RunChecks");
command!(history, "History");

#[tauri::command]
async fn set_plugin_enabled(id: String, enabled: bool) -> Result<Value, Value> {
    core("SetPluginEnabled", json!({ "id": id, "enabled": enabled }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn get_manifest(id: String) -> Result<Value, Value> {
    core("GetPlugin", json!({ "id": id }))
        .await
        .map(|value| value["manifest"].clone())
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn plan_change(plugin: String, patch: Value) -> Result<Value, Value> {
    core("PlanChange", json!({ "plugin": plugin, "patch": patch }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn apply(plan_id: String, confirm_timeout_s: Option<i64>) -> Result<Value, Value> {
    core(
        "Apply",
        json!({ "plan_id": plan_id, "confirm_timeout_s": confirm_timeout_s }),
    )
    .await
    .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn confirm(transaction_id: String) -> Result<Value, Value> {
    core("Confirm", json!({ "transaction_id": transaction_id }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn rollback(target: String) -> Result<Value, Value> {
    core("Rollback", json!({ "target": target }))
        .await
        .map_err(|e| err_text(&e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_info,
            get_posture,
            list_plugins,
            list_findings,
            run_checks,
            history,
            set_plugin_enabled,
            get_manifest,
            plan_change,
            apply,
            confirm,
            rollback,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the IbexWall app");
}
