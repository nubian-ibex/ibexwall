// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which firewall manager the machine has, and whether it is filtering.
//! IbexWall installs and starts nothing: when there is none, or it is off,
//! the person is given the distribution's own command.

use std::collections::BTreeMap;

use ibexwall_firewall::Backend;
use ibexwall_firewall::detect;
use ibexwall_proto::Finding;
use ibexwall_sdk::{Sandbox, detect::detected, detect::install_command};

use super::Files;

pub fn firewall(sandbox: &Sandbox, at: &str) -> Finding {
    let (backend, active) = detect::detect(&Files(sandbox));
    let mut args = BTreeMap::new();
    let case = match (backend, active) {
        (Backend::Firewalld, Some(true)) => {
            args.insert("manager".into(), "firewalld".into());
            "active"
        }
        (Backend::Ufw, Some(true)) => {
            args.insert("manager".into(), "ufw".into());
            "active"
        }
        (Backend::Firewalld, Some(false)) => {
            args.insert("manager".into(), "firewalld".into());
            args.insert(
                "start".into(),
                "sudo systemctl enable --now firewalld".into(),
            );
            "inactive"
        }
        (Backend::Ufw, Some(false)) => {
            args.insert("manager".into(), "ufw".into());
            args.insert("start".into(), "sudo ufw enable".into());
            "inactive"
        }
        _ => {
            // Debian and Ubuntu ship ufw as their usual manager; the others
            // ship firewalld.
            let debian = sandbox
                .read("/etc/os-release")
                .is_some_and(|r| r.contains("debian") || r.contains("ubuntu"));
            let package = if debian { "ufw" } else { "firewalld" };
            args.insert("package".into(), package.into());
            args.insert(
                "install".into(),
                install_command(sandbox, package)
                    .unwrap_or_else(|| format!("your package manager: {package}")),
            );
            "none"
        }
    };
    detected("net.firewall", "firewall", case, args, None, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-fwdet-{name}-{}", std::process::id()));
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

    #[test]
    fn active_inactive_and_missing_managers_are_told_apart_with_the_distros_own_commands() {
        let (r1, running) = machine(
            "on",
            &[("/run/systemd/units/invocation:firewalld.service", "")],
        );
        let note = firewall(&running, "x");
        assert_eq!(
            (note.summary_key.as_str(), note.args["manager"].as_str()),
            ("detect-firewall-active", "firewalld")
        );

        let (r2, off) = machine("off", &[("/usr/bin/firewall-cmd", "")]);
        let note = firewall(&off, "x");
        assert_eq!(note.summary_key, "detect-firewall-inactive");
        assert_eq!(note.args["start"], "sudo systemctl enable --now firewalld");

        let (r3, fedora) = machine("none", &[("/etc/os-release", "ID=fedora\n")]);
        let note = firewall(&fedora, "x");
        assert_eq!(note.summary_key, "detect-firewall-none");
        assert_eq!(note.args["install"], "sudo dnf install firewalld");
        let (r4, ubuntu) = machine(
            "ubuntu",
            &[("/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n")],
        );
        assert_eq!(
            firewall(&ubuntu, "x").args["install"],
            "sudo apt install ufw"
        );
        assert!(
            !note.args.contains_key("patch"),
            "nothing is started or installed for the person"
        );
        for r in [r1, r2, r3, r4] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }
}
