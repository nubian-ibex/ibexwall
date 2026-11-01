// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The change engine (spec §4.5): validation gate, snapshots, ordered
//! execution, inverses for rollback, and the confirm-window state
//! machine. Synchronous by design; the API layer runs it in blocking
//! tasks. Highest coverage target in the project (>= 90%).

pub mod exec;
pub mod ops;

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use ibexwall_proto::{Op, RiskFlag, UnitAction};
use ibexwall_sys::{Clock, Fs, RealClock, RealFs, RealSysctl, RealSystemd, Sysctl, Systemd};
use sha2::Digest;

use crate::state::State;

pub use ops::OpError;

/// System bundle the engine executes against; fakes for tests.
pub struct SysBundle {
    pub fs: Arc<dyn Fs>,
    pub systemd: Arc<dyn Systemd>,
    pub sysctl: Arc<dyn Sysctl>,
    pub clock: Arc<dyn Clock>,
    /// System-level executors (nft, exec, package installs) are refused
    /// while running under `IBEXWALL_ROOT` so the dev host is never
    /// touched.
    pub allow_system_executors: bool,
}

impl Default for SysBundle {
    fn default() -> Self {
        Self::real()
    }
}

impl SysBundle {
    pub fn real() -> Self {
        Self::real_under(&ibexwall_proto::names::root())
    }

    /// Real implementations bound to a sandbox root: file and sysctl
    /// paths are translated under it; systemd and system executors are
    /// refused unless the root is the real `/`.
    pub fn real_under(root: &std::path::Path) -> Self {
        let real_root = root == std::path::Path::new("/");
        Self {
            fs: Arc::new(RealFs::with_root(root.to_path_buf())),
            systemd: Arc::new(RealSystemd::new()),
            sysctl: Arc::new(RealSysctl::with_root(root.to_path_buf())),
            clock: Arc::new(RealClock),
            allow_system_executors: real_root,
        }
    }
}

/// A plan as persisted between the Plan and Apply calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPlan {
    pub id: String,
    pub plugin: String,
    /// JSON array of `Op`.
    pub ops_json: String,
    pub requires_confirm: bool,
    pub confirm_timeout_s: i64,
    pub fingerprint: String,
    pub expires_at: String,
    pub created_at: String,
}

impl PersistedPlan {
    pub fn ops(&self) -> Result<Vec<Op>> {
        Ok(serde_json::from_str(&self.ops_json)?)
    }
}

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

pub struct Engine {
    pub sys: SysBundle,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            sys: SysBundle::real(),
        }
    }

    pub fn with(sys: SysBundle) -> Self {
        Self { sys }
    }

    /// Preview rows for the UI (op kind, target, risk).
    pub fn preview(&self, ops: &[Op]) -> Vec<ibexwall_proto::OpPreview> {
        ops.iter()
            .enumerate()
            .map(|(index, op)| ibexwall_proto::OpPreview {
                op: op_name(op).to_string(),
                target: op_target(op),
                diff: op_diff(op, index),
                risk: ops::risk_flags(std::slice::from_ref(op)),
            })
            .collect()
    }

    /// Captures prior state for every op under
    /// `<state>/snapshots/<tx>/`.
    pub fn snapshot(&self, state: &State, tx: &str, ops: &[Op]) -> Result<SnapshotManifest> {
        let dir = state.snapshots_dir().join(tx);
        std::fs::create_dir_all(dir.join("files"))?;
        let mut entries = Vec::new();
        for (index, op) in ops.iter().enumerate() {
            match op {
                Op::FileWrite { path, .. } | Op::FileRemove { path } => {
                    let prior = match self.sys.fs.read(std::path::Path::new(path)) {
                        Ok(content) => {
                            let meta = self.sys.fs.metadata(std::path::Path::new(path))?;
                            let blob = format!("{index:03}.bin");
                            std::fs::write(dir.join("files").join(&blob), &content)?;
                            Some(PriorFile {
                                sha256: hex::encode(sha2::Sha256::digest(&content)),
                                blob,
                                mode: meta.mode,
                                uid: meta.uid,
                                gid: meta.gid,
                            })
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => {
                            return Err(
                                anyhow::Error::new(e).context(format!("snapshotting {path}"))
                            );
                        }
                    };
                    entries.push(SnapshotEntry::File {
                        op_index: index,
                        path: path.clone(),
                        prior,
                    });
                }
                Op::SystemdUnit { unit, .. } => {
                    let snapshot = self.sys.systemd.snapshot(unit)?;
                    entries.push(SnapshotEntry::Unit {
                        op_index: index,
                        unit: unit.clone(),
                        enabled: serde_json::to_string(&snapshot.enabled)?,
                        active: snapshot.active,
                    });
                }
                Op::SysctlSet { key, .. } => {
                    let prior = self.sys.sysctl.get(key).ok();
                    entries.push(SnapshotEntry::Sysctl {
                        op_index: index,
                        key: key.clone(),
                        prior,
                    });
                }
                _ => entries.push(SnapshotEntry::NoInverse { op_index: index }),
            }
        }
        let manifest = SnapshotManifest {
            tx: tx.to_string(),
            entries,
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(manifest)
    }

    /// Executes ops in order (idempotent; snapshot must exist first).
    pub fn execute(&self, ops: &[Op]) -> Result<()> {
        for op in ops {
            exec::execute(op, &self.sys).with_context(|| format!("executing {}", op_name(op)))?;
        }
        Ok(())
    }

    /// Applies inverses in reverse order from the snapshot manifest.
    pub fn rollback(&self, state: &State, tx: &str) -> Result<()> {
        let dir = state.snapshots_dir().join(tx);
        let bytes = std::fs::read(dir.join("manifest.json"))
            .with_context(|| format!("reading snapshot for {tx}"))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&bytes)?;
        for entry in manifest.entries.iter().rev() {
            match entry {
                SnapshotEntry::File { path, prior, .. } => match prior {
                    Some(prior_file) => {
                        let content = std::fs::read(dir.join("files").join(&prior_file.blob))?;
                        let digest = hex::encode(sha2::Sha256::digest(&content));
                        if digest != prior_file.sha256 {
                            anyhow::bail!("snapshot blob integrity failure for {path}");
                        }
                        self.sys.fs.write_atomic(
                            std::path::Path::new(path),
                            &content,
                            prior_file.mode,
                            Some((prior_file.uid, prior_file.gid)),
                        )?;
                    }
                    None => {
                        self.sys.fs.remove(std::path::Path::new(path))?;
                    }
                },
                SnapshotEntry::Unit {
                    unit,
                    enabled,
                    active,
                    ..
                } => {
                    let enabled: ibexwall_sys::Enabled = serde_json::from_str(enabled)?;
                    match enabled {
                        ibexwall_sys::Enabled::Enabled => {
                            self.sys.systemd.apply(unit, UnitAction::Enable, false)?;
                            if *active {
                                self.sys.systemd.apply(unit, UnitAction::Start, false)?;
                            }
                        }
                        ibexwall_sys::Enabled::Disabled => {
                            self.sys.systemd.apply(unit, UnitAction::Disable, false)?;
                            if *active {
                                self.sys.systemd.apply(unit, UnitAction::Start, false)?;
                            } else {
                                self.sys.systemd.apply(unit, UnitAction::Stop, false)?;
                            }
                        }
                        ibexwall_sys::Enabled::Masked => {
                            self.sys.systemd.apply(unit, UnitAction::Mask, false)?;
                        }
                        ibexwall_sys::Enabled::Static | ibexwall_sys::Enabled::NotFound => {
                            if *active {
                                self.sys.systemd.apply(unit, UnitAction::Start, false)?;
                            } else {
                                self.sys.systemd.apply(unit, UnitAction::Stop, false)?;
                            }
                        }
                    }
                }
                SnapshotEntry::Sysctl { key, prior, .. } => {
                    if let Some(value) = prior {
                        self.sys.sysctl.set(key, value)?;
                    }
                }
                SnapshotEntry::NoInverse { .. } => {}
            }
        }
        Ok(())
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::FileWrite { .. } => "file.write",
        Op::FileRemove { .. } => "file.remove",
        Op::SystemdUnit { .. } => "systemd.unit",
        Op::SysctlSet { .. } => "sysctl.set",
        Op::NftFragment { .. } => "nft.fragment",
        Op::FirewallAdapter { .. } => "firewall.adapter",
        Op::DnsBackend { .. } => "dns.backend",
        Op::FlatpakOverride { .. } => "flatpak.override",
        Op::SnapInterface { .. } => "snap.interface",
        Op::BrowserPolicy { .. } => "browser.policy",
        Op::NmSetting { .. } => "nm.setting",
        Op::PackageInstall { .. } => "package.install",
        Op::Exec { .. } => "exec",
    }
}

fn op_target(op: &Op) -> String {
    match op {
        Op::FileWrite { path, .. } | Op::FileRemove { path } => path.clone(),
        Op::SystemdUnit { unit, action, .. } => format!("{action:?} {unit}"),
        Op::SysctlSet { key, value } => format!("{key} = {value}"),
        Op::NftFragment { fragment } => fragment
            .get("chain")
            .or_else(|| fragment.get("set"))
            .and_then(|v| v.as_str())
            .unwrap_or("fragment")
            .into(),
        Op::FirewallAdapter { backend, .. } | Op::DnsBackend { backend, .. } => backend.clone(),
        Op::FlatpakOverride { app_id, .. } => app_id.clone(),
        Op::SnapInterface {
            snap, interface, ..
        } => format!("{snap}:{interface}"),
        Op::BrowserPolicy { browser, .. } => browser.clone(),
        Op::NmSetting { key, .. } => key.clone(),
        Op::PackageInstall { package } => package.clone(),
        Op::Exec { path, .. } => path.clone(),
    }
}

fn op_diff(op: &Op, index: usize) -> Option<String> {
    match op {
        Op::FileWrite { content, .. } => Some(
            content
                .lines()
                .map(|line| format!("+{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Op::FileRemove { .. } => Some(format!("-{index:03}: file removed")),
        _ => None,
    }
}

/// Aggregated flags helper used by the API layer.
pub fn flags_from(ops: &[Op]) -> Vec<RiskFlag> {
    ops::risk_flags(ops)
}
