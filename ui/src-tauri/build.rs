// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Declaring the app commands makes Tauri generate one `allow-<command>`
// permission each, so a window can be given only the commands it needs
// (the prompt window gets three; see capabilities/prompt.json). Keep this
// list equal to `generate_handler!` in src/lib.rs.
const COMMANDS: &[&str] = &[
    "get_info",
    "get_posture",
    "get_dns_status",
    "list_apps",
    "get_firewall",
    "get_app_destinations",
    "set_app_mode",
    "set_default_mode",
    "list_prompts",
    "answer_prompt",
    "finish_prompt",
    "list_plugins",
    "list_compliance_profiles",
    "get_compliance",
    "get_effective",
    "list_findings",
    "run_checks",
    "history",
    "list_restore_points",
    "create_restore_point",
    "restore_point_plan",
    "restore_point_apply",
    "get_system_snapshots",
    "set_system_snapshots",
    "export_state",
    "import_state",
    "list_proposals",
    "decide_proposal",
    "set_plugin_enabled",
    "set_monitor_enabled",
    "get_config",
    "get_app_info",
    "get_manifest",
    "plan_change",
    "apply",
    "confirm",
    "rollback",
    "make_assistant_token",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run the Tauri build script");
}
