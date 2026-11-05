// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the machine does with DNS today, said before anything is changed.

use std::collections::BTreeMap;

use ibexwall_proto::Finding;
use ibexwall_sdk::{Sandbox, detect::detected};
use serde_json::json;

use super::{Backend, backend, dropin_points_at_resolver, network_servers, resolver_listening};

/// Whether systemd-resolved is told to use TLS (`yes` or `opportunistic`).
fn resolved_uses_tls(sandbox: &Sandbox) -> bool {
    let mut texts = vec![
        sandbox
            .read("/etc/systemd/resolved.conf")
            .unwrap_or_default(),
    ];
    for name in sandbox.list("/etc/systemd/resolved.conf.d") {
        if name.ends_with(".conf")
            && let Some(text) = sandbox.read(&format!("/etc/systemd/resolved.conf.d/{name}"))
        {
            texts.push(text);
        }
    }
    texts
        .iter()
        .flat_map(|t| t.lines())
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.strip_prefix("DNSOverTLS="))
        .next_back()
        .is_some_and(|v| matches!(v.trim(), "yes" | "true" | "opportunistic"))
}

/// The other stacks a machine may run, by what is installed or running.
fn other_stack(sandbox: &Sandbox) -> &'static str {
    if sandbox.exists("/run/NetworkManager") {
        "NetworkManager"
    } else if sandbox.exists("/usr/sbin/unbound") || sandbox.exists("/usr/bin/unbound") {
        "unbound"
    } else if sandbox.exists("/usr/sbin/dnsmasq") || sandbox.exists("/usr/bin/dnsmasq") {
        "dnsmasq"
    } else {
        "a fixed /etc/resolv.conf"
    }
}

pub fn dns(sandbox: &Sandbox, at: &str) -> Finding {
    let servers = network_servers(sandbox).join(", ");
    let mut args = BTreeMap::from([("servers".to_string(), servers)]);
    let case = match backend::detect(sandbox) {
        Backend::Resolved if dropin_points_at_resolver(sandbox) && resolver_listening(sandbox) => {
            "ibexwall"
        }
        Backend::Resolved if resolved_uses_tls(sandbox) => {
            args.insert("stack".into(), "systemd-resolved".into());
            "resolved-tls"
        }
        Backend::Resolved => {
            args.insert("stack".into(), "systemd-resolved".into());
            "resolved-plain"
        }
        Backend::Unsupported(_) => {
            args.insert("stack".into(), other_stack(sandbox).into());
            "other"
        }
    };
    // The suggestion is only the starting point of a review: the person
    // still sees the plan and applies it.
    let patch = (case == "resolved-plain")
        .then(|| json!({ "provider": "quad9", "transport": "tls", "enforcement": false }));
    detected("net.dns", "dns", case, args, patch, at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn machine(
        name: &str,
        resolved: bool,
        files: &[(&str, &str)],
    ) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-dnsdet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        if resolved {
            std::fs::create_dir_all(root.join("run/systemd/resolve")).unwrap();
            symlink(
                "../run/systemd/resolve/stub-resolv.conf",
                root.join("etc/resolv.conf"),
            )
            .unwrap();
            std::fs::write(
                root.join("run/systemd/resolve/resolv.conf"),
                "nameserver 192.168.1.1\n",
            )
            .unwrap();
        }
        for (path, text) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, text).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    #[test]
    fn plain_resolved_gets_a_suggestion_and_names_what_the_network_offers() {
        let (root, sandbox) = machine("plain", true, &[]);
        let note = dns(&sandbox, "x");
        assert_eq!(note.summary_key, "detect-dns-resolved-plain");
        assert_eq!(note.args["servers"], "192.168.1.1");
        assert_eq!(note.args["stack"], "systemd-resolved");
        assert!(note.args["patch"].contains("quad9"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolved_already_using_tls_is_left_alone() {
        let (root, sandbox) = machine(
            "tls",
            true,
            &[(
                "/etc/systemd/resolved.conf.d/dot.conf",
                "[Resolve]\nDNSOverTLS=yes\n",
            )],
        );
        let note = dns(&sandbox, "x");
        assert_eq!(note.summary_key, "detect-dns-resolved-tls");
        assert!(!note.args.contains_key("patch"));
        // A commented line does not count.
        let (root2, off) = machine(
            "off",
            true,
            &[("/etc/systemd/resolved.conf", "[Resolve]\n#DNSOverTLS=yes\n")],
        );
        assert_eq!(dns(&off, "x").summary_key, "detect-dns-resolved-plain");
        for r in [root, root2] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    #[test]
    fn other_stacks_are_named_and_not_guessed_at() {
        let (root, sandbox) = machine("nm", false, &[("/run/NetworkManager/x", "")]);
        let note = dns(&sandbox, "x");
        assert_eq!(
            (note.summary_key.as_str(), note.args["stack"].as_str()),
            ("detect-dns-other", "NetworkManager")
        );
        assert!(!note.args.contains_key("patch"));
        let (root2, bare) = machine("bare", false, &[]);
        assert_eq!(dns(&bare, "x").args["stack"], "a fixed /etc/resolv.conf");
        for r in [root, root2] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }
}
