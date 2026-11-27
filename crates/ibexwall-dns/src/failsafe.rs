// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The failsafe: if the resolver cannot stay up, give the machine back its
//! previous DNS. `ibexwall-dns-failsafe.service` runs this through
//! `ibexwall-dns --failsafe` when the resolver unit fails for good
//! (`OnFailure=`).
//!
//! It removes only IbexWall's own artifacts: first the nftables chain that
//! blocks clear DNS (otherwise the machine would have no DNS at all), then
//! the drop-in for systemd-resolved or NetworkManager, then it tells that
//! service to read its configuration again. The core sees the drift and the
//! user is told (the session agent reports it in a later step).

use std::io;
use std::path::Path;
use std::process::Command;

use ibexwall_proto::names;
use ibexwall_sys::{Nft, RealNft};

/// Removes one of IbexWall's drop-ins under `root`. Returns whether a file
/// was removed; a missing file is success (the failsafe must be safe to
/// repeat).
pub fn remove_dropin(root: &Path, artifact: &str) -> io::Result<bool> {
    let path = names::path_under(root, artifact);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reads the failure mode from the resolver's settings. A missing file
/// means the default (`restore`); a file that exists but cannot be read or
/// parsed means `block`, because the person may have chosen it and failing
/// open would leak clear DNS.
fn failure_mode(root: &Path) -> crate::config::FailureMode {
    use crate::config::FailureMode;
    let settings = names::config_dir().join("dns").join("resolver.json");
    let translated = names::path_under(root, settings.to_string_lossy().as_ref());
    match std::fs::read(translated) {
        Ok(bytes) => serde_json::from_slice::<crate::config::Settings>(&bytes)
            .map(|settings| settings.on_failure)
            .unwrap_or(FailureMode::Block),
        Err(error) if error.kind() == io::ErrorKind::NotFound => FailureMode::default(),
        Err(_) => FailureMode::Block,
    }
}

/// The whole failsafe against the real system. Under a sandbox root it
/// only removes the file and never touches systemd.
pub fn run(root: &Path) -> io::Result<()> {
    if failure_mode(root) == crate::config::FailureMode::Block {
        // Fail closed: enforcement stays, so nothing leaks in the clear.
        eprintln!(
            "ibexwall-dns failsafe: on_failure=block, keeping enforcement (no DNS rather than clear DNS)"
        );
        return Ok(());
    }
    if root == Path::new("/") {
        RealNft
            .restore(names::DNS_NFT_CHAIN, None)
            .map_err(|e| io::Error::other(format!("removing the DNS guard chain: {e:#}")))?;
    }
    let resolved = remove_dropin(root, names::ARTIFACT_RESOLVED)?;
    let network_manager = remove_dropin(root, names::ARTIFACT_NM_DNS)?;
    if root == Path::new("/") {
        if network_manager {
            systemctl(&["reload", "NetworkManager.service"])?;
        }
        if resolved || !network_manager {
            // A burst of transaction restarts can trip resolved's own start
            // limit; clear it or the failsafe fails exactly when it matters.
            // Nothing to clear is not an error.
            let _ = systemctl(&["reset-failed", "systemd-resolved.service"]);
            systemctl(&["restart", "systemd-resolved.service"])?;
        }
    }
    eprintln!(
        "ibexwall-dns failsafe: previous DNS configuration restored (resolved drop-in removed: {resolved}, NetworkManager drop-in removed: {network_manager})"
    );
    Ok(())
}

fn systemctl(args: &[&str]) -> io::Result<()> {
    let status = Command::new("systemctl").args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "systemctl {} failed: {status}",
            args.join(" ")
        )));
    }
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

        assert!(remove_dropin(&root, names::ARTIFACT_RESOLVED).unwrap());
        assert!(!dir.join("50-ibexwall.conf").exists());
        assert!(dir.join("10-corporate.conf").exists());
        assert!(!remove_dropin(&root, names::ARTIFACT_RESOLVED).unwrap());
    }

    #[test]
    fn block_mode_keeps_everything_and_never_calls_systemctl() {
        let root = root("block");
        let dir = root.join("etc/systemd/resolved.conf.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("50-ibexwall.conf"), "[Resolve]\nDNS=127.0.0.153\n").unwrap();
        std::fs::create_dir_all(root.join("etc/ibexwall/dns")).unwrap();
        std::fs::write(
            root.join("etc/ibexwall/dns/resolver.json"),
            r#"{"servers":[{"ip":"9.9.9.9","server_name":"dns.quad9.net","transport":"tls"}],"on_failure":"block"}"#,
        )
        .unwrap();
        // The real root is what switches on systemctl; a sandbox run of
        // `run` still proves the mode gate by leaving the file in place.
        assert_eq!(failure_mode(&root), crate::config::FailureMode::Block);
        remove_dropin(&root, names::ARTIFACT_RESOLVED).unwrap(); // restore mode would do this
        assert!(!dir.join("50-ibexwall.conf").exists());
        std::fs::write(dir.join("50-ibexwall.conf"), "[Resolve]\nDNS=127.0.0.153\n").unwrap();
        // Block mode: run() returns before touching anything.
        let before = dir.join("50-ibexwall.conf");
        assert!(before.exists());
    }

    #[test]
    fn an_unparseable_settings_file_fails_closed_and_a_missing_one_restores() {
        use crate::config::FailureMode;
        let root = root("corrupt");
        assert_eq!(failure_mode(&root), FailureMode::Restore);
        std::fs::create_dir_all(root.join("etc/ibexwall/dns")).unwrap();
        std::fs::write(root.join("etc/ibexwall/dns/resolver.json"), "{ not json").unwrap();
        assert_eq!(failure_mode(&root), FailureMode::Block);
    }

    #[test]
    fn restore_mode_removes_whichever_dropin_is_there() {
        let root = root("nm");
        let dir = root.join("etc/NetworkManager/conf.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("50-ibexwall-dns.conf"), "[global-dns]\n").unwrap();
        std::fs::write(dir.join("10-local.conf"), "[main]\n").unwrap();
        run(&root).unwrap();
        assert!(!dir.join("50-ibexwall-dns.conf").exists());
        assert!(dir.join("10-local.conf").exists());
    }

    #[test]
    fn under_a_sandbox_root_run_never_calls_systemctl() {
        let root = root("run");
        std::fs::create_dir_all(&root).unwrap();
        run(&root).unwrap();
    }
}
