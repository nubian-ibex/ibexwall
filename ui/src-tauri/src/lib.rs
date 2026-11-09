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
/// The methods that change the machine. The app is a person at their
/// desktop, so it lets the daemon ask for their password (ADR-0045).
const ASKS_FOR_PASSWORD: &[&str] = &[
    "SetPluginEnabled",
    "SetMonitorEnabled",
    "Apply",
    "Confirm",
    "Rollback",
    "DecideProposal",
];

async fn core(method: &str, mut parameters: Value) -> Result<Value, String> {
    if ASKS_FOR_PASSWORD.contains(&method)
        && let Some(map) = parameters.as_object_mut()
    {
        map.insert("allowInteractiveAuthentication".into(), Value::Bool(true));
    }
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
/// Calls one Policy method.
async fn policy(method: &str) -> Result<Value, String> {
    let socket = names::core_socket();
    let mut client = ibexwall_varlink::Client::connect(&socket)
        .await
        .map_err(|e| format!("unreachable: {e}"))?;
    client
        .call(&format!("com.ibexwall.Policy.{method}"), json!({}))
        .await
        .map_err(|e| json!({ "code": e.name, "parameters": e.parameters }).to_string())
        .and_then(|value| serde_json::from_value(value).map_err(|e| format!("bad reply: {e}")))
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
command!(list_compliance_profiles, "ListComplianceProfiles");

#[tauri::command]
async fn get_compliance(profile: String) -> Result<Value, Value> {
    core("GetCompliance", json!({ "profile": profile }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn get_effective() -> Result<Value, Value> {
    policy("GetEffective").await.map_err(|e| err_text(&e))
}

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
async fn list_proposals(status: Option<String>) -> Result<Value, Value> {
    core("ListProposals", json!({ "status": status }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn decide_proposal(id: String, decision: String) -> Result<Value, Value> {
    core("DecideProposal", json!({ "id": id, "decision": decision }))
        .await
        .map_err(|e| err_text(&e))
}

#[tauri::command]
async fn set_monitor_enabled(enabled: bool) -> Result<Value, Value> {
    core("SetMonitorEnabled", json!({ "enabled": enabled }))
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

/// Tray labels follow the session language, like the UI.
fn tray_labels() -> (&'static str, &'static str, &'static str) {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    let code = lang.to_lowercase();
    if code.starts_with("pt") {
        ("Abrir o IbexWall", "Sair", "IbexWall")
    } else if code.starts_with("es") {
        ("Abrir IbexWall", "Salir", "IbexWall")
    } else if code.starts_with("fr") {
        ("Ouvrir IbexWall", "Quitter", "IbexWall")
    } else if code.starts_with("de") {
        ("IbexWall öffnen", "Beenden", "IbexWall")
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

/// Makes an access token here, so its secret never travels through the core:
/// the screen shows it once and sends the plan only the Argon2id hash.
#[tauri::command]
fn make_assistant_token(
    name: String,
    preset: String,
    client: Option<String>,
    id: Option<String>,
    expires: Option<String>,
    secret: Option<String>,
) -> Result<Value, Value> {
    let fail = |reason: String| json!({ "code": "com.ibexwall.Core.InvalidArgument", "parameters": { "reason": reason } });
    let id = match id.filter(|i| !i.is_empty()) {
        Some(id) => id,
        None => ibexwall_token::random_bytes(4)
            .map_err(|e| fail(e.to_string()))?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    let client = client
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("remote-{id}"));
    let expires = expires.filter(|e| !e.is_empty());
    let created = ibexwall_token::create(
        &id,
        &name,
        &client,
        expires.as_deref(),
        secret.as_deref().filter(|s| !s.is_empty()),
    )
    .map_err(fail)?;
    let hash = created
        .stanza
        .lines()
        .find_map(|l| l.strip_prefix("hash = \""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or_default()
        .to_string();
    let mut patch = json!({
        "action": "token_add", "id": id, "name": name,
        "client": client, "preset": preset, "hash": hash,
    });
    if let Some(day) = expires {
        patch["expires"] = json!(day);
    }
    Ok(json!({ "token": created.token, "patch": patch }))
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
            list_compliance_profiles,
            get_compliance,
            get_effective,
            list_findings,
            run_checks,
            history,
            list_proposals,
            decide_proposal,
            set_plugin_enabled,
            set_monitor_enabled,
            get_manifest,
            plan_change,
            apply,
            confirm,
            rollback,
            make_assistant_token,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the IbexWall app");
}
