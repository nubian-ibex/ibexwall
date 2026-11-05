// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `apps.flatpak-network`: cuts the network access of chosen Flatpak apps.
//! (`apps.flatpak_perms`, the permissions audit, is a separate F7 plugin.)
//!
//! The plugin only proposes `flatpak.override` operations; the core
//! snapshots, applies and, on request, rolls them back (the file Flatpak
//! reads returns byte for byte). Scope: the default system-wide Flatpak
//! installation. Per-user installs live in home directories the core does
//! not read (`ProtectHome`), so they are out of reach by design.
//!
//! Config: `{"app": "org.x.App"}` or `{"block": ["org.x.App", ...]}`.

use ibexwall_proto::{CheckReport, Op};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

/// Where the system installation keeps its applications.
const APPS_DIR: &str = "/var/lib/flatpak/app";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(FlatpakPerms)) {
        eprintln!("ibexwall-plugin-flatpak-network: {err}");
        std::process::exit(1);
    }
}

struct FlatpakPerms;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    app: Option<String>,
    block: Vec<String>,
}

impl Plugin for FlatpakPerms {
    fn id(&self) -> &'static str {
        "apps.flatpak-network"
    }

    /// Nothing here is a pass or a fail: an app having network access is
    /// the normal state, and what the user blocked is shown by the Apps
    /// screen. The check exists so the plugin can be enabled and listed.
    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![],
            findings: vec![],
        })
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), config)
    }

    async fn verify(&self, _transaction: &str, ops: &[Op]) -> bool {
        let sandbox = Sandbox::system();
        ops.iter().all(|op| match op {
            Op::FlatpakOverride { app_id, .. } => is_blocked(&sandbox, app_id),
            _ => true,
        })
    }
}

fn is_blocked(sandbox: &Sandbox, app_id: &str) -> bool {
    ibexwall_sys::flatpak::override_path(app_id)
        .is_some_and(|path| ibexwall_sys::flatpak::network_blocked(sandbox.read(&path).as_deref()))
}

fn plan(sandbox: &Sandbox, config: Config) -> Result<Vec<Op>, PluginError> {
    let mut apps = config.block;
    apps.extend(config.app);
    apps.sort();
    apps.dedup();
    if apps.is_empty() {
        return Err(PluginError::invalid(
            "app",
            "name an app: {\"app\": \"org.example.App\"}".to_string(),
        ));
    }
    let installed = sandbox.list(APPS_DIR);
    let mut ops = Vec::new();
    for app in apps {
        if !ibexwall_sys::flatpak::valid_app_id(&app) {
            return Err(PluginError::invalid(
                "app",
                format!("`{app}` is not an application id"),
            ));
        }
        // Refuse names that are not installed: a typo would otherwise
        // leave a stray override file behind.
        if !installed.contains(&app) {
            return Err(PluginError::invalid(
                "app",
                format!("`{app}` is not a Flatpak app installed system-wide"),
            ));
        }
        ops.push(Op::FlatpakOverride {
            app_id: app,
            args: vec![ibexwall_sys::flatpak::UNSHARE_NETWORK.to_string()],
        });
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(apps: &[&str], overrides: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-flatpak-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        for app in apps {
            std::fs::create_dir_all(root.join("var/lib/flatpak/app").join(app)).unwrap();
        }
        for (app, content) in overrides {
            let dir = root.join("var/lib/flatpak/overrides");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(app), content).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    fn config(app: Option<&str>, block: &[&str]) -> Config {
        Config {
            app: app.map(str::to_string),
            block: block.iter().map(|b| b.to_string()).collect(),
        }
    }

    #[test]
    fn plans_one_override_per_installed_app_sorted_and_deduplicated() {
        let (root, sandbox) = tree(&["org.a.One", "org.b.Two"], &[]);
        let ops = plan(
            &sandbox,
            config(Some("org.b.Two"), &["org.a.One", "org.b.Two"]),
        )
        .unwrap();
        assert_eq!(
            ops,
            vec![
                Op::FlatpakOverride {
                    app_id: "org.a.One".into(),
                    args: vec!["--unshare=network".into()]
                },
                Op::FlatpakOverride {
                    app_id: "org.b.Two".into(),
                    args: vec!["--unshare=network".into()]
                },
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_unknown_invalid_and_missing_apps() {
        let (root, sandbox) = tree(&["org.a.One"], &[]);
        for bad in [
            config(Some("org.a.Typo"), &[]),
            config(Some("../../etc"), &[]),
            config(Some("org.a.One\n"), &[]),
            config(None, &[]),
        ] {
            assert!(plan(&sandbox, bad).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        let result: Result<Config, _> =
            serde_json::from_value(serde_json::json!({"app": "org.a.One", "filesystem": "host"}));
        assert!(result.is_err());
    }

    #[test]
    fn verify_sees_the_block_in_the_override_file() {
        let (root, sandbox) = tree(
            &["org.a.One", "org.b.Two"],
            &[("org.a.One", "[Context]\nshared=!network;\n")],
        );
        assert!(is_blocked(&sandbox, "org.a.One"));
        assert!(!is_blocked(&sandbox, "org.b.Two"));
        assert!(!is_blocked(&sandbox, "../x"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
