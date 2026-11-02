// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Operation execution, snapshot manifests and inverses. Shared by the
//! core (which plans, snapshots and audits) and the `ibexwall-exec`
//! helper that runs inside a transient unit whose `ReadWritePaths` are
//! limited to one transaction (ADR-0026).

use std::io::Write;
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
    },
    Sysctl {
        op_index: usize,
        key: String,
        prior: Option<String>,
    },
    /// Ops without a system inverse (exec).
    NoInverse { op_index: usize },
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
        let path = match op {
            Op::FileWrite { path, .. } | Op::FileRemove { path } => path.as_str(),
            _ => continue,
        };
        if let Some(parent) = Path::new(path).parent() {
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
            apply_nft_fragment(fragment)
        }
        Op::FirewallAdapter { .. } => {
            Err(not_implemented("firewall.adapter", "adapter lands in F5"))
        }
        Op::DnsBackend { .. } => Err(not_implemented("dns.backend", "adapter lands in F3")),
        Op::FlatpakOverride { .. } => Err(not_implemented("flatpak.override", "lands in F4")),
        Op::SnapInterface { .. } => Err(not_implemented("snap.interface", "lands in F4")),
        Op::BrowserPolicy { .. } => Err(not_implemented("browser.policy", "lands in F3")),
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

/// Applies a fragment to `table inet ibexwall` atomically through the
/// nftables JSON API: `nft -c -j` precheck, then `nft -j -f -`.
fn apply_nft_fragment(fragment: &serde_json::Value) -> Result<()> {
    let batch = serde_json::json!({
        "nftables": [
            { "table": { "family": "inet", "name": ibexwall_proto::names::NFT_TABLE } },
            fragment.clone(),
        ]
    });
    let payload = serde_json::to_vec(&batch)?;

    for check in [true, false] {
        let mut command = Command::new("nft");
        command.arg("-j");
        if check {
            command.arg("-c");
        }
        command.arg("-f").arg("-");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context("spawning nft")?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&payload)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "nft {} failed: {}",
                if check { "check" } else { "apply" },
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(())
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
            SnapshotEntry::NoInverse { .. } => {}
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
    }
}
