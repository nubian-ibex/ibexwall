// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Operation execution, snapshot manifests and inverses. Shared by the
//! core (which plans, snapshots and audits) and the `ibexwall-exec`
//! helper that runs inside a transient unit whose `ReadWritePaths` are
//! limited to one transaction (ADR-0026).

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use ibexwall_proto::{Op, UnitAction};

/// One snapshot entry; inverses replay them backwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotEntry {
    File {
        op_index: usize,
        path: String,
        /// None: the file did not exist.
        prior: Option<PriorFile>,
    },
    Unit {
        op_index: usize,
        unit: String,
        enabled: String,
        active: bool,
        /// The forward op restarted the unit, so rollback restarts it
        /// again once the files it reads are restored.
        #[serde(default)]
        restarted: bool,
    },
    Sysctl {
        op_index: usize,
        key: String,
        prior: Option<String>,
    },
    /// Chains an `nft.fragment` replaced, with what each held before.
    Nft {
        op_index: usize,
        chains: Vec<NftChainPrior>,
    },
    /// Ops without a system inverse (exec).
    NoInverse { op_index: usize },
}

/// A chain's definition before a transaction (`None`: it did not exist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftChainPrior {
    pub name: String,
    pub prior: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorFile {
    /// File name inside the snapshot directory.
    pub blob: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub tx: String,
    pub entries: Vec<SnapshotEntry>,
}

/// Errors from executing one operation (validation lives in the core).
#[derive(Debug, thiserror::Error)]
pub enum OpError {
    #[error("op `{op}` has no executor yet ({detail})")]
    NotImplemented {
        op: &'static str,
        detail: &'static str,
    },
    #[error("system-level executors are disabled while running under IBEXWALL_ROOT")]
    SandboxBlocked,
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Parent directories a set of ops needs to write to (deduped, sorted) —
/// the `ReadWritePaths` of the transient executor unit.
pub fn write_directories(ops: &[Op]) -> Vec<String> {
    let mut dirs: std::collections::BTreeSet<String> = Default::default();
    for op in ops {
        let path: String = match op {
            Op::FileWrite { path, .. } | Op::FileRemove { path } => path.clone(),
            // The browser policy executor writes one known file per
            // browser; its directory must be writable in the unit too.
            Op::BrowserPolicy { browser, .. } => match crate::browser::target(browser) {
                Some(target) => target.path.to_string(),
                None => continue,
            },
            // Likewise one override file per Flatpak application.
            Op::FlatpakOverride { app_id, .. } => match crate::flatpak::override_path(app_id) {
                Some(path) => path,
                None => continue,
            },
            _ => continue,
        };
        if let Some(parent) = Path::new(&path).parent() {
            let parent = parent.to_string_lossy();
            if !parent.is_empty() {
                dirs.insert(parent.into_owned());
            }
        }
    }
    dirs.into_iter().collect()
}

/// Executes one operation against the system bundle.
pub fn execute(op: &Op, sys: &crate::SysBundle) -> Result<()> {
    match op {
        Op::FileWrite {
            path,
            content,
            mode,
            owner,
            group,
        } => {
            let mode = parse_mode(mode).ok_or_else(|| OpError::Invalid {
                field: "mode",
                reason: format!("`{mode}` is not octal"),
            })?;
            let uid = resolve_user(owner)?;
            let gid = resolve_group(group)?;
            // Ownership changes need root; unprivileged sandbox runs
            // keep the creating user's ownership.
            let owner = if crate::current_uid() == 0 {
                Some((uid, gid))
            } else {
                None
            };
            // Drop-in directories may legitimately not exist yet
            // (e.g. resolved.conf.d on minimal systems).
            if let Some(parent) = Path::new(path).parent() {
                sys.fs.create_dir_all(parent).map_err(anyhow::Error::from)?;
            }
            sys.fs
                .write_atomic(Path::new(path), content.as_bytes(), mode, owner)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("writing {path}"))?;
            Ok(())
        }
        Op::FileRemove { path } => {
            sys.fs
                .remove(Path::new(path))
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        Op::SystemdUnit { unit, action, now } => {
            let now = now.unwrap_or(true);
            sys.systemd.apply(unit, *action, now)?;
            Ok(())
        }
        Op::SysctlSet { key, value } => {
            sys.sysctl.set(key, value)?;
            Ok(())
        }
        Op::Exec { path, args } => {
            if !sys.allow_system_executors {
                return Err(OpError::SandboxBlocked.into());
            }
            let status = Command::new(path)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .status()
                .with_context(|| format!("spawning {path}"))?;
            if !status.success() {
                bail!("exec {path} failed with {status}");
            }
            Ok(())
        }
        Op::NftFragment { fragment } => {
            if !sys.allow_system_executors {
                return Err(OpError::SandboxBlocked.into());
            }
            let fragment = parse_fragment(fragment)?;
            sys.nft.apply(&fragment)
        }
        Op::FirewallAdapter { .. } => {
            Err(not_implemented("firewall.adapter", "adapter lands in F5"))
        }
        Op::DnsBackend { .. } => Err(not_implemented("dns.backend", "adapter lands in F3")),
        Op::FlatpakOverride { app_id, args } => {
            let path = crate::flatpak::override_path(app_id).ok_or_else(|| OpError::Invalid {
                field: "flatpak.override",
                reason: format!("`{app_id}` is not an application id"),
            })?;
            if !crate::flatpak::args_allowed(args) {
                return Err(OpError::Invalid {
                    field: "flatpak.override",
                    reason: "only --unshare=network is supported".into(),
                }
                .into());
            }
            let path = Path::new(&path);
            let existing = sys
                .fs
                .read(path)
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            let content = crate::flatpak::unshare_network(existing.as_deref());
            // Already blocked: leave the file (and its mtime) alone.
            if existing.as_deref() == Some(content.as_str()) {
                return Ok(());
            }
            if let Some(parent) = path.parent() {
                sys.fs.create_dir_all(parent).map_err(anyhow::Error::from)?;
            }
            sys.fs
                .write_atomic(path, content.as_bytes(), 0o644, None)
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        Op::SnapInterface { .. } => Err(not_implemented("snap.interface", "lands in F4")),
        Op::BrowserPolicy { browser, policy } => {
            let target = crate::browser::target(browser).ok_or_else(|| OpError::Invalid {
                field: "browser.policy",
                reason: format!("unknown browser `{browser}`"),
            })?;
            if &serde_json::from_str::<serde_json::Value>(target.content).map_err(|_| {
                OpError::Invalid {
                    field: "browser.policy",
                    reason: "internal policy content is not JSON".into(),
                }
            })? != policy
            {
                return Err(OpError::Invalid {
                    field: "browser.policy",
                    reason: "only the exact disable-DoH policy may be written".into(),
                }
                .into());
            }
            let path = std::path::Path::new(target.path);
            if let Ok(existing) = sys.fs.read(path)
                && !existing.is_empty()
                && !crate::browser::is_ours(browser, &existing)
            {
                // Firefox's file name is fixed: never touch an
                // administrator's policy file.
                return Err(OpError::Invalid {
                    field: "browser.policy",
                    reason: format!("{} already has a policy file", target.path),
                }
                .into());
            }
            if let Some(parent) = path.parent() {
                sys.fs.create_dir_all(parent).map_err(anyhow::Error::from)?;
            }
            sys.fs
                .write_atomic(path, target.content.as_bytes(), 0o644, None)
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        Op::NmSetting { .. } => Err(not_implemented("nm.setting", "lands in F3")),
        Op::PackageInstall { .. } => Err(not_implemented(
            "package.install",
            "PackageKit flow lands in F7",
        )),
    }
}

fn not_implemented(op: &'static str, detail: &'static str) -> anyhow::Error {
    OpError::NotImplemented { op, detail }.into()
}

fn parse_mode(mode: &str) -> Option<u32> {
    u32::from_str_radix(mode, 8).ok().filter(|m| *m <= 0o7777)
}

fn resolve_user(owner: &str) -> Result<u32> {
    match owner {
        "root" => Ok(0),
        numeric => Ok(numeric.parse::<u32>().map_err(|_| OpError::Invalid {
            field: "owner",
            reason: format!("`{owner}`: only `root` or a numeric uid in F1"),
        })?),
    }
}

fn resolve_group(group: &str) -> Result<u32> {
    match group {
        "root" => Ok(0),
        numeric => Ok(numeric.parse::<u32>().map_err(|_| OpError::Invalid {
            field: "group",
            reason: format!("`{group}`: only `root` or a numeric gid in F1"),
        })?),
    }
}

/// Parses the typed fragment a plugin proposed.
pub fn parse_fragment(value: &serde_json::Value) -> Result<crate::Fragment> {
    let fragment: crate::Fragment =
        serde_json::from_value(value.clone()).map_err(|e| OpError::Invalid {
            field: "nft.fragment",
            reason: e.to_string(),
        })?;
    fragment.validate().map_err(|e| OpError::Invalid {
        field: "nft.fragment",
        reason: e.to_string(),
    })?;
    Ok(fragment)
}

/// Reads a snapshot manifest and applies the inverses in reverse order.
/// `snapshot_root` is the directory that contains `<tx>/manifest.json`
/// and `<tx>/files/`.
pub fn apply_snapshot_inverses(
    sys: &crate::SysBundle,
    snapshot_root: &Path,
    manifest: &SnapshotManifest,
) -> Result<()> {
    let dir = snapshot_root.join(&manifest.tx);
    for entry in manifest.entries.iter().rev() {
        match entry {
            SnapshotEntry::File { path, prior, .. } => match prior {
                Some(prior_file) => {
                    let content = std::fs::read(dir.join("files").join(&prior_file.blob))?;
                    let digest = hex::encode(Sha256::digest(&content));
                    if digest != prior_file.sha256 {
                        bail!("snapshot blob integrity failure for {path}");
                    }
                    sys.fs.write_atomic(
                        Path::new(path),
                        &content,
                        prior_file.mode,
                        Some((prior_file.uid, prior_file.gid)),
                    )?;
                }
                None => {
                    sys.fs.remove(Path::new(path))?;
                }
            },
            SnapshotEntry::Unit {
                unit,
                enabled,
                active,
                ..
            } => {
                let enabled: crate::Enabled = serde_json::from_str(enabled)?;
                match enabled {
                    crate::Enabled::Enabled => {
                        sys.systemd.apply(unit, UnitAction::Enable, false)?;
                        if *active {
                            sys.systemd.apply(unit, UnitAction::Start, false)?;
                        } else {
                            sys.systemd.apply(unit, UnitAction::Stop, false)?;
                        }
                    }
                    crate::Enabled::Disabled => {
                        sys.systemd.apply(unit, UnitAction::Disable, false)?;
                        if *active {
                            sys.systemd.apply(unit, UnitAction::Start, false)?;
                        } else {
                            sys.systemd.apply(unit, UnitAction::Stop, false)?;
                        }
                    }
                    crate::Enabled::Masked => {
                        sys.systemd.apply(unit, UnitAction::Stop, false)?;
                        sys.systemd.apply(unit, UnitAction::Mask, false)?;
                    }
                    crate::Enabled::Static | crate::Enabled::NotFound => {
                        if *active {
                            sys.systemd.apply(unit, UnitAction::Start, false)?;
                        } else {
                            sys.systemd.apply(unit, UnitAction::Stop, false)?;
                        }
                    }
                }
            }
            SnapshotEntry::Sysctl { key, prior, .. } => {
                if let Some(value) = prior {
                    sys.sysctl.set(key, value)?;
                }
            }
            SnapshotEntry::Nft { chains, .. } => {
                for chain in chains {
                    sys.nft.restore(&chain.name, chain.prior.as_ref())?;
                }
            }
            SnapshotEntry::NoInverse { .. } => {}
        }
    }
    // Second pass: services restarted by the transaction pick up the
    // restored files. Only units that were running before are restarted;
    // a stopped one was already stopped by the first pass.
    for entry in &manifest.entries {
        if let SnapshotEntry::Unit {
            unit,
            active: true,
            restarted: true,
            ..
        } = entry
        {
            sys.systemd.apply(unit, UnitAction::Restart, false)?;
        }
    }
    Ok(())
}

/// SHA-256 of the serialized ops, for audit entries.
pub fn ops_digest(ops: &[Op]) -> String {
    let bytes = serde_jcs::to_vec(ops).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(name: &str) -> (std::path::PathBuf, crate::SysBundle) {
        let root = std::env::temp_dir().join(format!("ibexwall-ops-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sys = crate::SysBundle::real_under(&root);
        (root, sys)
    }

    fn block(app_id: &str) -> Op {
        Op::FlatpakOverride {
            app_id: app_id.into(),
            args: vec!["--unshare=network".into()],
        }
    }

    #[test]
    fn flatpak_override_writes_the_known_file_and_merges_into_an_existing_one() {
        let (root, sys) = sandbox("flatpak");
        let dir = root.join("var/lib/flatpak/overrides");

        execute(&block("org.example.Fresh"), &sys).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("org.example.Fresh")).unwrap(),
            "[Context]\nshared=!network;\n"
        );

        std::fs::write(
            dir.join("org.example.Mine"),
            "[Context]\nshared=ipc;\nfilesystems=home;\n",
        )
        .unwrap();
        execute(&block("org.example.Mine"), &sys).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("org.example.Mine")).unwrap(),
            "[Context]\nshared=ipc;!network;\nfilesystems=home;\n"
        );

        // Doing it again changes nothing, not even the bytes.
        let before = std::fs::read(dir.join("org.example.Mine")).unwrap();
        execute(&block("org.example.Mine"), &sys).unwrap();
        assert_eq!(std::fs::read(dir.join("org.example.Mine")).unwrap(), before);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn flatpak_override_refuses_anything_but_the_one_change() {
        let (root, sys) = sandbox("flatpak-refuse");
        for op in [
            block("../../etc/passwd"),
            block("firefox"),
            Op::FlatpakOverride {
                app_id: "org.example.App".into(),
                args: vec!["--filesystem=host".into()],
            },
            Op::FlatpakOverride {
                app_id: "org.example.App".into(),
                args: vec![],
            },
        ] {
            assert!(execute(&op, &sys).is_err(), "{op:?}");
        }
        assert!(!root.join("var").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn write_directories_include_the_flatpak_overrides_directory() {
        assert_eq!(
            write_directories(&[block("org.example.App"), block("org.other.App")]),
            vec!["/var/lib/flatpak/overrides".to_string()]
        );
        // An invalid id contributes nothing.
        assert!(write_directories(&[block("nope")]).is_empty());
    }

    #[test]
    fn write_directories_are_parent_dirs_deduped_and_sorted() {
        let ops = [
            Op::FileWrite {
                path: "/etc/sysctl.d/a.conf".into(),
                content: String::new(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::FileRemove {
                path: "/etc/sysctl.d/b.conf".into(),
            },
            Op::FileRemove {
                path: "/etc/NetworkManager/conf.d/c.conf".into(),
            },
            Op::SysctlSet {
                key: "k".into(),
                value: "1".into(),
            },
        ];
        assert_eq!(
            write_directories(&ops),
            vec![
                "/etc/NetworkManager/conf.d".to_string(),
                "/etc/sysctl.d".to_string()
            ]
        );
        let with_browser = [
            Op::BrowserPolicy {
                browser: "firefox".into(),
                policy: serde_json::json!({}),
            },
            Op::BrowserPolicy {
                browser: "brave".into(),
                policy: serde_json::json!({}),
            },
        ];
        assert_eq!(
            write_directories(&with_browser),
            vec![
                "/etc/brave/policies/managed".to_string(),
                "/etc/firefox/policies".to_string()
            ]
        );
    }
}
