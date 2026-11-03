// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall desktop shell. The Rust side is a thin varlink client: the UI
//! logic lives in the web frontend and talks to these typed commands.
//! No remote content, no updater (updates come from the distro).

use ibexwall_proto::names;
use serde_json::{Value, json};
use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

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
command!(get_dns_status, "GetDnsStatus");
command!(list_apps, "ListApps");
command!(get_firewall, "GetFirewall");
command!(list_plugins, "ListPlugins");
command!(list_findings, "ListFindings");
command!(run_checks, "RunChecks");
command!(history, "History");
command!(list_prompts, "ListPrompts");

#[tauri::command]
async fn get_app_destinations(app: String) -> Result<Value, Value> {
    core("GetAppDestinations", json!({ "app": app }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn set_app_mode(app: String, mode: String) -> Result<Value, Value> {
    core("SetAppMode", json!({ "app": app, "mode": mode }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn set_default_mode(mode: String) -> Result<Value, Value> {
    core("SetDefaultMode", json!({ "mode": mode }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn answer_prompt(id: String, decision: String, scope: String) -> Result<Value, Value> {
    core(
        "AnswerPrompt",
        json!({ "id": id, "decision": decision, "scope": scope }),
    )
    .await
    .map_err(|e| err_text(&e))
}

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

/// Tray labels follow the session language (en or pt-BR), like the UI.
fn tray_labels() -> (&'static str, &'static str, &'static str) {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    if lang.to_lowercase().starts_with("pt") {
        ("Abrir o IbexWall", "Sair", "IbexWall")
    } else {
        ("Open IbexWall", "Quit", "IbexWall")
    }
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let (open_label, quit_label, tooltip) = tray_labels();
    let open = MenuItem::with_id(app, "open", open_label, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", quit_label, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut tray = TrayIconBuilder::new()
        .tooltip(tooltip)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

/// `ibexwall --prompt`: the held connection alone, in its own small window
/// (mockup 05), with no tray and no main window.
fn prompt_mode() -> bool {
    std::env::args().any(|arg| arg == "--prompt")
}

/// The prompt window asks to end the process once nothing is waiting.
#[tauri::command]
fn finish_prompt(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if prompt_mode() {
                if let Some(main) = app.get_webview_window("main") {
                    let _ = main.destroy();
                }
                tauri::WebviewWindowBuilder::new(
                    app,
                    "prompt",
                    tauri::WebviewUrl::App("index.html?window=prompt".into()),
                )
                .title("IbexWall")
                .inner_size(440.0, 600.0)
                .resizable(false)
                .always_on_top(true)
                .center()
                .build()?;
            } else {
                build_tray(app)?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_info,
            get_posture,
            get_dns_status,
            list_apps,
            get_firewall,
            get_app_destinations,
            set_app_mode,
            set_default_mode,
            list_prompts,
            answer_prompt,
            finish_prompt,
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
