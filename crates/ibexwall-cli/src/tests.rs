// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn the_read_commands_print_something_a_person_can_read() {
    use serde_json::json;
    let status = render_status(
        &json!({ "info": { "version": "0.1.0", "api": 1, "distro": "fedora", "kernel": "7.2", "degraded": [] } }),
    );
    assert_eq!(
        status,
        "ibexwalld 0.1.0 (api 1) on fedora, kernel 7.2\nnothing degraded\n"
    );
    let plugins = render_plugins(
        &json!({ "plugins": [{ "id": "net.dns", "enabled": false, "status": "ok", "name": "Secure DNS" }] }),
    );
    assert!(
        plugins.contains("net.dns") && plugins.contains("off") && plugins.contains("Secure DNS")
    );
    assert_eq!(render_findings(&json!({ "findings": [] })), "no findings\n");
    let findings = render_findings(
        &json!({ "findings": [{ "severity": "high", "id": "x.y", "plugin": "p" }] }),
    );
    assert!(findings.contains("high") && findings.contains("x.y"));
    assert_eq!(
        render_history(&json!({ "entries": [] })),
        "no changes yet\n"
    );
    assert_eq!(render_events(&json!({ "events": [] })), "no events yet\n");
    // Text from outside never carries a terminal escape.
    let hostile = render_findings(
        &json!({ "findings": [{ "severity": "low", "id": "\u{1b}[2J", "plugin": "p" }] }),
    );
    assert!(!hostile.contains('\u{1b}'));
}
use super::*;
use serde_json::json;

#[test]
fn control_characters_never_reach_the_terminal() {
    assert_eq!(clean("evil\u{1b}[31m\nname"), "evil?[31m?name");
    let out = render_apps(&json!({
        "monitor": {"running": true, "reason": null},
        "apps": [{
            "key": "cli:/tmp/\u{1b}]0;pwned\u{7}",
            "kind": "cli", "connections": 3, "destinations": 1,
            "last_seen": "2026-11-03T10:00:00Z"
        }]
    }));
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
    assert!(out.contains("cli:/tmp/?]0;pwned?"));
}

#[test]
fn the_list_says_whether_the_monitor_is_off_and_why() {
    let off = render_apps(&json!({
        "monitor": {"running": false, "reason": "waiting for ibexwall-monitor"},
        "apps": []
    }));
    assert!(off.starts_with("monitor: off (waiting for ibexwall-monitor)"));
    assert!(off.contains("no applications seen yet"));
    let degraded = render_apps(&json!({
        "monitor": {"running": true, "reason": "kernel-side exec capture is off"},
        "apps": []
    }));
    assert!(degraded.starts_with("monitor: running (kernel-side exec capture is off)"));
}

#[test]
fn info_marks_destinations_without_a_domain() {
    let out = render_app_info(
        &json!({"key": "cli:/usr/bin/curl", "kind": "cli", "exe_path": "/usr/bin/curl",
                "package": "curl", "first_seen": "a", "last_seen": "b", "connections": 2}),
        &json!([
            {"destination": "example.com", "resolved": true, "port": 443, "count": 2, "last_seen": "b"},
            {"destination": "203.0.113.7", "resolved": false, "port": 80, "count": 1, "last_seen": "b"}
        ]),
    );
    assert!(out.contains("example.com:443  x2"));
    assert!(out.contains("203.0.113.7:80  x1  last b  (no domain)"));
}

#[test]
fn a_target_becomes_the_plugins_setting() {
    assert_eq!(
        firewall_patch("8080/tcp", true),
        json!({"allow": "8080/tcp"})
    );
    assert_eq!(firewall_patch("22", false), json!({"remove": "22"}));
    assert_eq!(
        firewall_patch("service:http", true),
        json!({"allow_service": "http"})
    );
    assert_eq!(
        firewall_patch("service:http", false),
        json!({"remove_service": "http"})
    );
}

#[test]
fn the_firewall_status_is_readable_and_terminal_safe() {
    let out = render_firewall(&json!({
        "backend": "firewalld", "active": true, "zone": "pub\u{1b}lic",
        "ports": [{"port": 8080, "proto": "tcp"}],
        "services": ["ssh", "http"],
        "listening": [{"port": 22, "proto": "tcp"}],
        "other": ["rich rule: x\u{7}"]
    }));
    assert!(out.starts_with("firewall: firewalld (active), zone pub?lic\n"));
    assert!(out.contains("allowed ports:    8080/tcp"));
    assert!(out.contains("allowed services: ssh, http"));
    assert!(out.contains("listening on every address: 22/tcp"));
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'));
    let bare = render_firewall(&json!({
        "backend": "nftables", "active": false,
        "ports": [], "services": [], "listening": [], "other": []
    }));
    assert!(bare.contains("nftables (not active)"));
    assert!(bare.contains("allowed ports:    none"));
}
