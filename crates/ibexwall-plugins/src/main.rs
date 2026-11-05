// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The official plugins in one binary (ADR-0041). It is started under a
//! plugin's own name, `ibexwall-plugin-<name>`, through a link: each plugin
//! is still its own process in its own unit and sandbox, only the file on
//! disk is shared. Third-party plugins keep shipping their own binary.

use std::path::Path;

/// The plugin names this binary can be: the part after `ibexwall-plugin-`.
pub const PLUGINS: &[&str] = &[
    "flatpak-network",
    "flatpak-perms",
    "usb",
    "av",
    "integrity",
    "isolate",
    "persistence",
    "dns",
    "firewall",
    "nts",
    "vpn",
    "wifi",
    "camera-mic",
    "telemetry",
    "accounts",
    "audit",
    "coredump",
    "firmware",
    "mounts",
    "ports",
    "posture",
    "session-lock",
    "ssh",
    "assistant",
    "sysctl",
    "updates",
    "cves",
];

/// `ibexwall-plugin-vpn` and `/usr/lib/.../ibexwall-plugin-vpn` both name `vpn`.
fn plugin_name(argv0: &str) -> Option<&str> {
    Path::new(argv0)
        .file_name()?
        .to_str()?
        .strip_prefix("ibexwall-plugin-")
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let Some(name) = plugin_name(&argv0) else {
        eprintln!(
            "ibexwall-plugins: start me through a link named ibexwall-plugin-<name>; I can be: {}",
            PLUGINS.join(", ")
        );
        std::process::exit(2);
    };
    match name {
        "flatpak-network" => ibexwall_plugin_flatpak_network::run(),
        "flatpak-perms" => ibexwall_plugin_flatpak_perms::run(),
        "usb" => ibexwall_plugin_usb::run(),
        "av" => ibexwall_plugin_av::run(),
        "integrity" => ibexwall_plugin_integrity::run(),
        "isolate" => ibexwall_plugin_isolate::run(),
        "persistence" => ibexwall_plugin_persistence::run(),
        "dns" => ibexwall_plugin_dns::run(),
        "firewall" => ibexwall_plugin_firewall::run(),
        "nts" => ibexwall_plugin_nts::run(),
        "vpn" => ibexwall_plugin_vpn::run(),
        "wifi" => ibexwall_plugin_wifi::run(),
        "camera-mic" => ibexwall_plugin_camera_mic::run(),
        "telemetry" => ibexwall_plugin_telemetry::run(),
        "accounts" => ibexwall_plugin_accounts::run(),
        "audit" => ibexwall_plugin_audit::run(),
        "coredump" => ibexwall_plugin_coredump::run(),
        "firmware" => ibexwall_plugin_firmware::run(),
        "mounts" => ibexwall_plugin_mounts::run(),
        "ports" => ibexwall_plugin_ports::run(),
        "posture" => ibexwall_plugin_posture::run(),
        "session-lock" => ibexwall_plugin_session_lock::run(),
        "ssh" => ibexwall_plugin_ssh::run(),
        "assistant" => ibexwall_plugin_assistant::run(),
        "sysctl" => ibexwall_plugin_sysctl::run(),
        "updates" => ibexwall_plugin_updates::run(),
        "cves" => ibexwall_plugin_cves::run(),
        other => {
            eprintln!("ibexwall-plugins: no plugin named `{other}`");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plugin_is_chosen_by_the_name_the_binary_was_started_under() {
        assert_eq!(plugin_name("ibexwall-plugin-vpn"), Some("vpn"));
        assert_eq!(
            plugin_name("/usr/lib/ibexwall/plugins/net.vpn/ibexwall-plugin-vpn"),
            Some("vpn")
        );
        assert_eq!(plugin_name("ibexwall-plugins"), None);
        assert_eq!(plugin_name("ibexctl"), None);
        assert_eq!(plugin_name(""), None);
    }

    #[test]
    fn every_plugin_manifest_names_a_binary_this_one_can_be() {
        // The manifests are the source of truth for what ships.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
        let mut found = 0;
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let manifest = entry.path().join("plugin.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            let binary = text
                .lines()
                .find_map(|l| l.strip_prefix("binary = \""))
                .and_then(|l| l.strip_suffix('"'))
                .unwrap();
            let name = plugin_name(binary).unwrap();
            if entry.file_name() == "dev.echo" {
                continue; // the test plugin keeps its own binary
            }
            assert!(
                PLUGINS.contains(&name),
                "{} names {binary}, which the multicall binary does not know",
                entry.path().display()
            );
            found += 1;
        }
        assert_eq!(
            found,
            PLUGINS.len(),
            "a plugin in the binary has no manifest, or the other way round"
        );
    }
}
