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
                            } else {
                                self.sys.systemd.apply(unit, UnitAction::Stop, false)?;
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
                            self.sys.systemd.apply(unit, UnitAction::Stop, false)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    use ibexwall_sys::{Enabled, FakeClock, FakeFs, FakeSysctl, FakeSystemd, UnitSnapshot};
    use serde_json::json;
    use std::path::Path;

    struct Rig {
        engine: Engine,
        fs: Arc<FakeFs>,
        systemd: Arc<FakeSystemd>,
        sysctl: Arc<FakeSysctl>,
        state: State,
        dir: std::path::PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn rig(name: &str, allow_system: bool) -> Rig {
        let dir = std::env::temp_dir().join(format!("ibx-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fs = Arc::new(FakeFs::new());
        let systemd = Arc::new(FakeSystemd::new());
        let sysctl = Arc::new(FakeSysctl::new());
        let engine = Engine::with(SysBundle {
            fs: fs.clone(),
            systemd: systemd.clone(),
            sysctl: sysctl.clone(),
            clock: Arc::new(FakeClock::new(1_793_534_400)),
            allow_system_executors: allow_system,
        });
        Rig {
            engine,
            fs,
            systemd,
            sysctl,
            state: State::open(&dir).unwrap(),
            dir,
        }
    }

    fn write(path: &str, content: &str) -> Op {
        Op::FileWrite {
            path: path.into(),
            content: content.into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }
    }

    #[test]
    fn file_write_over_existing_file_rolls_back_to_prior_content() {
        let rig = rig("fw", false);
        let path = "/etc/sysctl.d/90-ibexwall-test.conf";
        rig.fs.seed(Path::new(path), b"old\n");
        let ops = vec![write(path, "new\n")];
        rig.engine.snapshot(&rig.state, "tx1", &ops).unwrap();
        rig.engine.execute(&ops).unwrap();
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"new\n");
        rig.engine.rollback(&rig.state, "tx1").unwrap();
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"old\n");
    }

    #[test]
    fn file_write_creating_a_file_is_undone_by_removal() {
        let rig = rig("fc", false);
        let path = "/etc/ibexwall-tests/new.conf";
        let ops = vec![write(path, "x\n")];
        rig.engine.snapshot(&rig.state, "tx2", &ops).unwrap();
        rig.engine.execute(&ops).unwrap();
        assert!(rig.fs.exists(Path::new(path)));
        rig.engine.rollback(&rig.state, "tx2").unwrap();
        assert!(!rig.fs.exists(Path::new(path)));
    }

    #[test]
    fn file_remove_is_restored_from_the_snapshot() {
        let rig = rig("fr", false);
        let path = "/etc/ibexwall-tests/keep.conf";
        rig.fs.seed(Path::new(path), b"keep\n");
        let ops = vec![Op::FileRemove { path: path.into() }];
        rig.engine.snapshot(&rig.state, "tx3", &ops).unwrap();
        rig.engine.execute(&ops).unwrap();
        assert!(!rig.fs.exists(Path::new(path)));
        rig.engine.rollback(&rig.state, "tx3").unwrap();
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"keep\n");
    }

    #[test]
    fn tampered_snapshot_blob_aborts_the_rollback() {
        let rig = rig("tb", false);
        let path = "/etc/ibexwall-tests/t.conf";
        rig.fs.seed(Path::new(path), b"orig\n");
        let ops = vec![write(path, "new\n")];
        rig.engine.snapshot(&rig.state, "tx4", &ops).unwrap();
        rig.engine.execute(&ops).unwrap();
        let blob = rig.state.snapshots_dir().join("tx4/files/000.bin");
        std::fs::write(&blob, b"evil\n").unwrap();
        let err = rig.engine.rollback(&rig.state, "tx4").unwrap_err();
        assert!(err.to_string().contains("integrity"), "{err}");
        // The live file was not overwritten with tampered data.
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"new\n");
    }

    #[test]
    fn rollback_without_a_snapshot_fails() {
        let rig = rig("ns", false);
        assert!(rig.engine.rollback(&rig.state, "missing").is_err());
    }

    #[test]
    fn unit_state_is_restored_for_each_prior_state() {
        for (enabled, active) in [
            (Enabled::Enabled, true),
            (Enabled::Enabled, false),
            (Enabled::Disabled, true),
            (Enabled::Disabled, false),
            (Enabled::Masked, false),
            (Enabled::Static, true),
            (Enabled::NotFound, false),
        ] {
            let rig = rig("unit", false);
            rig.systemd
                .seed("ibexwall-test.service", UnitSnapshot { enabled, active });
            let ops = vec![Op::SystemdUnit {
                unit: "ibexwall-test.service".into(),
                action: UnitAction::Restart,
                now: None,
            }];
            rig.engine.snapshot(&rig.state, "txu", &ops).unwrap();
            rig.engine.execute(&ops).unwrap();
            rig.engine.rollback(&rig.state, "txu").unwrap();
            let after = rig.systemd.get("ibexwall-test.service");
            assert_eq!(after.active, active, "{enabled:?}/{active}");
            if matches!(
                enabled,
                Enabled::Enabled | Enabled::Disabled | Enabled::Masked
            ) {
                assert_eq!(after.enabled, enabled);
            }
        }
    }

    #[test]
    fn sysctl_value_is_restored_and_unknown_keys_are_skipped() {
        let rig = rig("sc", false);
        rig.sysctl.seed("vm.swappiness", "60");
        let ops = vec![
            Op::SysctlSet {
                key: "vm.swappiness".into(),
                value: "10".into(),
            },
            Op::SysctlSet {
                key: "vm.unknown_key".into(),
                value: "1".into(),
            },
        ];
        rig.engine.snapshot(&rig.state, "txs", &ops).unwrap();
        rig.engine.execute(&ops).unwrap();
        assert_eq!(rig.sysctl.get("vm.swappiness").unwrap(), "10");
        rig.engine.rollback(&rig.state, "txs").unwrap();
        assert_eq!(rig.sysctl.get("vm.swappiness").unwrap(), "60");
    }

    #[test]
    fn exec_and_other_ops_have_no_system_inverse() {
        let rig = rig("ni", false);
        let ops = vec![Op::Exec {
            path: "/usr/bin/true".into(),
            args: vec![],
        }];
        let manifest = rig.engine.snapshot(&rig.state, "txn", &ops).unwrap();
        assert!(matches!(
            manifest.entries[0],
            SnapshotEntry::NoInverse { .. }
        ));
        rig.engine.rollback(&rig.state, "txn").unwrap();
    }

    #[test]
    fn execute_stops_at_the_first_failing_op() {
        let rig = rig("ef", false);
        let ops = vec![
            Op::Exec {
                path: "/usr/bin/true".into(),
                args: vec![],
            }, // sandbox-blocked
            write("/etc/ibexwall-tests/never.conf", "x"),
        ];
        assert!(rig.engine.execute(&ops).is_err());
        assert!(!rig.fs.exists(Path::new("/etc/ibexwall-tests/never.conf")));
    }

    #[test]
    fn preview_describes_every_op_kind() {
        let rig = rig("pv", false);
        let ops = vec![
            write("/etc/a.conf", "l1\nl2"),
            Op::FileRemove {
                path: "/etc/b.conf".into(),
            },
            Op::SystemdUnit {
                unit: "u.service".into(),
                action: UnitAction::Stop,
                now: None,
            },
            Op::SysctlSet {
                key: "k.x".into(),
                value: "1".into(),
            },
            Op::NftFragment {
                fragment: json!({ "chain": "dev_echo_c" }),
            },
            Op::NftFragment {
                fragment: json!({}),
            },
            Op::FirewallAdapter {
                backend: "ufw".into(),
                action: json!({}),
            },
            Op::DnsBackend {
                backend: "resolved".into(),
                action: json!({}),
            },
            Op::FlatpakOverride {
                app_id: "org.x.App".into(),
                args: vec!["--unshare=network".into()],
            },
            Op::SnapInterface {
                snap: "s".into(),
                interface: "network".into(),
                connect: false,
            },
            Op::BrowserPolicy {
                browser: "firefox".into(),
                policy: json!({"a": 1}),
            },
            Op::NmSetting {
                key: "k".into(),
                value: json!(1),
            },
            Op::PackageInstall {
                package: "chrony".into(),
            },
            Op::Exec {
                path: "/usr/bin/x".into(),
                args: vec![],
            },
        ];
        let preview = rig.engine.preview(&ops);
        assert_eq!(preview.len(), ops.len());
        assert_eq!(preview[0].diff.as_deref(), Some("+l1\n+l2"));
        assert!(preview[1].diff.as_deref().unwrap().contains("removed"));
        assert_eq!(preview[4].target, "dev_echo_c");
        assert_eq!(preview[5].target, "fragment");
        assert_eq!(preview[8].target, "org.x.App");
        assert_eq!(preview[9].target, "s:network");
        assert!(preview[12].risk.contains(&RiskFlag::Irreversible));
        assert_eq!(flags_from(&ops[12..13]), vec![RiskFlag::Irreversible]);
    }

    #[test]
    fn default_engine_is_bound_to_the_real_root_or_sandbox() {
        let engine = Engine::default();
        assert_eq!(
            engine.sys.allow_system_executors,
            ibexwall_proto::names::root() == Path::new("/")
        );
        let sandboxed = SysBundle::real_under(Path::new("/tmp/some-root"));
        assert!(!sandboxed.allow_system_executors);
    }
}
