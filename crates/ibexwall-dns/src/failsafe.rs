// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The failsafe: if the resolver cannot stay up, give the machine back its
//! previous DNS. `ibexwall-dns-failsafe.service` runs this through
//! `ibexwall-dns --failsafe` when the resolver unit fails for good
//! (`OnFailure=`).
//!
//! It removes only IbexWall's own drop-in and restarts the system
//! resolver; the core sees the drift and the user is told (the session
//! agent reports it in a later step).

use std::io;
use std::path::Path;
use std::process::Command;

use ibexwall_proto::names;

/// Removes the drop-in under `root`. Returns whether a file was removed;
/// a missing file is success (the failsafe must be safe to repeat).
pub fn remove_dropin(root: &Path) -> io::Result<bool> {
    let path = names::path_under(root, names::ARTIFACT_RESOLVED);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// The whole failsafe against the real system. Under a sandbox root it
/// only removes the file and never touches systemd.
pub fn run(root: &Path) -> io::Result<()> {
    let removed = remove_dropin(root)?;
    if root == Path::new("/") {
        let status = Command::new("systemctl")
            .args(["restart", "systemd-resolved.service"])
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "systemctl restart failed: {status}"
            )));
        }
    }
    eprintln!(
        "ibexwall-dns failsafe: previous DNS configuration restored (drop-in removed: {removed})"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("ibx-failsafe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn removes_only_the_ibexwall_dropin_and_is_repeatable() {
        let root = root("rm");
        let dir = root.join("etc/systemd/resolved.conf.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("50-ibexwall.conf"), "[Resolve]\nDNS=127.0.0.153\n").unwrap();
        std::fs::write(dir.join("10-corporate.conf"), "[Resolve]\nDNS=192.0.2.53\n").unwrap();

        assert!(remove_dropin(&root).unwrap());
        assert!(!dir.join("50-ibexwall.conf").exists());
        assert!(dir.join("10-corporate.conf").exists());
        assert!(!remove_dropin(&root).unwrap());
    }

    #[test]
    fn under_a_sandbox_root_run_never_calls_systemctl() {
        let root = root("run");
        std::fs::create_dir_all(&root).unwrap();
        run(&root).unwrap();
    }
}
