// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which DNS stack the machine uses, read from the system without
//! changing anything. An unsupported or unclear stack is refused with a
//! reason instead of guessed.

use ibexwall_sdk::Sandbox;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `/etc/resolv.conf` is managed by systemd-resolved. NetworkManager
    /// or systemd-networkd may feed it per-link servers; their interplay
    /// is handled in a later step (spike S3-b/c).
    Resolved,
    /// Not supported yet.
    Unsupported(&'static str),
}

pub fn detect(sandbox: &Sandbox) -> Backend {
    let resolv = sandbox.read_link("/etc/resolv.conf").unwrap_or_default();
    if resolv.contains("systemd/resolve") && sandbox.exists("/run/systemd/resolve") {
        return Backend::Resolved;
    }
    if sandbox.exists("/run/NetworkManager") {
        return Backend::Unsupported(
            "NetworkManager without systemd-resolved is not supported yet",
        );
    }
    Backend::Unsupported("this DNS configuration is not supported yet")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("ibx-dnsbe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        root
    }

    #[test]
    fn detects_resolved_by_the_resolv_conf_symlink() {
        let root = root("resolved");
        std::fs::create_dir_all(root.join("run/systemd/resolve")).unwrap();
        symlink(
            "../run/systemd/resolve/stub-resolv.conf",
            root.join("etc/resolv.conf"),
        )
        .unwrap();
        assert_eq!(detect(&Sandbox::at(&root)), Backend::Resolved);
    }

    #[test]
    fn a_plain_resolv_conf_is_not_resolved() {
        let root = root("plain");
        std::fs::write(root.join("etc/resolv.conf"), "nameserver 192.0.2.1\n").unwrap();
        assert!(matches!(
            detect(&Sandbox::at(&root)),
            Backend::Unsupported(_)
        ));
    }

    #[test]
    fn networkmanager_alone_is_reported_specifically() {
        let root = root("nm");
        std::fs::create_dir_all(root.join("run/NetworkManager")).unwrap();
        let Backend::Unsupported(reason) = detect(&Sandbox::at(&root)) else {
            panic!("expected unsupported");
        };
        assert!(reason.contains("NetworkManager"));
    }
}
