// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What keeps the clock today, and whether it can tell a real time server
//! from a forged one.

use std::collections::BTreeMap;

use ibexwall_proto::Finding;
use ibexwall_sdk::{Sandbox, detect::detected, detect::install_command};
use serde_json::json;

use super::{chrony_installed, sources};

fn timesyncd(sandbox: &Sandbox) -> bool {
    [
        "/usr/lib/systemd/system/systemd-timesyncd.service",
        "/lib/systemd/system/systemd-timesyncd.service",
    ]
    .iter()
    .any(|p| sandbox.exists(p))
}

fn ntpd(sandbox: &Sandbox) -> bool {
    sandbox.exists("/usr/sbin/ntpd") || sandbox.exists("/usr/bin/ntpd")
}

pub fn time(sandbox: &Sandbox, at: &str) -> Finding {
    let mut args = BTreeMap::new();
    let mut patch = None;
    let case = if chrony_installed(sandbox) {
        match sources(sandbox) {
            Some(list) if list.iter().any(|(_, nts)| *nts) => {
                let nts = list.iter().filter(|(_, nts)| *nts).count();
                args.insert("sources".into(), nts.to_string());
                "chrony-nts"
            }
            Some(list) => {
                args.insert("sources".into(), list.len().to_string());
                patch = Some(json!({ "preset": "cloudflare" }));
                "chrony-plain"
            }
            None => "chrony-unreadable",
        }
    } else {
        // IbexWall installs nothing: the person gets the distro's command.
        args.insert(
            "install".into(),
            install_command(sandbox, "chrony")
                .unwrap_or_else(|| "your package manager: chrony".into()),
        );
        if timesyncd(sandbox) {
            "timesyncd"
        } else if ntpd(sandbox) {
            "ntpd"
        } else {
            "none"
        }
    };
    detected("net.nts", "time", case, args, patch, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-ntsdet-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, text) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, text).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    const FEDORA: (&str, &str) = ("/etc/os-release", "ID=fedora\n");
    const CHRONYD: (&str, &str) = ("/usr/sbin/chronyd", "");

    #[test]
    fn chrony_with_and_without_nts_and_the_clients_that_cannot_authenticate() {
        let (r1, plain) = machine(
            "plain",
            &[
                CHRONYD,
                ("/etc/chrony.conf", "pool 2.pool.ntp.org iburst\n"),
            ],
        );
        let note = time(&plain, "x");
        assert_eq!(note.summary_key, "detect-time-chrony-plain");
        assert!(note.args["patch"].contains("cloudflare"));

        let (r2, secure) = machine(
            "nts",
            &[
                CHRONYD,
                (
                    "/etc/chrony.conf",
                    "server time.cloudflare.com iburst nts\n",
                ),
            ],
        );
        let note = time(&secure, "x");
        assert_eq!(note.summary_key, "detect-time-chrony-nts");
        assert!(!note.args.contains_key("patch"));

        let (r3, sd) = machine(
            "sd",
            &[
                FEDORA,
                ("/usr/lib/systemd/system/systemd-timesyncd.service", ""),
            ],
        );
        let note = time(&sd, "x");
        assert_eq!(note.summary_key, "detect-time-timesyncd");
        assert_eq!(note.args["install"], "sudo dnf install chrony");
        assert!(
            !note.args.contains_key("patch"),
            "IbexWall installs nothing"
        );

        let (r4, ntp) = machine("ntp", &[FEDORA, ("/usr/sbin/ntpd", "")]);
        assert_eq!(time(&ntp, "x").summary_key, "detect-time-ntpd");
        let (r5, none) = machine("none", &[]);
        let note = time(&none, "x");
        assert_eq!(note.summary_key, "detect-time-none");
        assert!(note.args["install"].contains("chrony"));
        for r in [r1, r2, r3, r4, r5] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }
}
