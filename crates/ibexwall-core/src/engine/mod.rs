// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The change engine (spec §4.5): validation gate, snapshots, ordered
//! execution, inverses for rollback, and the confirm-window state
//! machine. Synchronous by design; the API layer runs it in blocking
//! tasks. Highest coverage target in the project (>= 90%).

pub mod ops;

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::State;
use ibexwall_proto::{Op, RiskFlag};
use sha2::Digest;

use ibexwall_sys::{PriorFile, SnapshotEntry, SnapshotManifest};

pub use crate::engine::ops::OpError as ValidateError;

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

pub struct Engine {
    pub sys: ibexwall_sys::SysBundle,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            sys: ibexwall_sys::SysBundle::real(),
        }
    }

    pub fn with(sys: ibexwall_sys::SysBundle) -> Self {
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
                Op::SystemdUnit { unit, action, .. } => {
                    let snapshot = self.sys.systemd.snapshot(unit)?;
                    entries.push(SnapshotEntry::Unit {
                        op_index: index,
                        unit: unit.clone(),
                        enabled: serde_json::to_string(&snapshot.enabled)?,
                        active: snapshot.active,
                        restarted: *action == ibexwall_proto::UnitAction::Restart,
                    });
                }
                Op::BrowserPolicy { .. } | Op::FlatpakOverride { .. } => {
                    // The inverse is the file the executor writes, captured
                    // like any other file so rollback restores or removes it.
                    let path: String = match op {
                        Op::BrowserPolicy { browser, .. } => ibexwall_sys::browser::target(browser)
                            .map(|target| target.path.to_string())
                            .ok_or_else(|| {
                                anyhow::anyhow!("unknown browser `{browser}` for browser.policy")
                            })?,
                        Op::FlatpakOverride { app_id, .. } => {
                            ibexwall_sys::flatpak::override_path(app_id).ok_or_else(|| {
                                anyhow::anyhow!("`{app_id}` is not an application id")
                            })?
                        }
                        _ => unreachable!("matched above"),
                    };
                    let path = path.as_str();
                    let prior = match self.sys.fs.read(Path::new(path)) {
                        Ok(content) if !content.is_empty() => {
                            let meta = self.sys.fs.metadata(Path::new(path))?;
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
                        _ => None,
                    };
                    entries.push(SnapshotEntry::File {
                        op_index: index,
                        path: path.into(),
                        prior,
                    });
                }
                Op::FirewallAdapter { backend, action } => {
                    // The manager rewrites its own files: capture them, and
                    // note that rollback must tell it to re-read them.
                    let (kind, action) = ibexwall_sys::ops::parse_firewall(backend, action)?;
                    let default_zone = self
                        .sys
                        .fs
                        .read(Path::new("/etc/firewalld/firewalld.conf"))
                        .ok()
                        .and_then(|bytes| {
                            ibexwall_firewall::parse::firewalld_default_zone(
                                &String::from_utf8_lossy(&bytes),
                            )
                        })
                        // firewalld's own default when the file names none.
                        .unwrap_or_else(|| "public".into());
                    entries.push(SnapshotEntry::Firewall {
                        op_index: index,
                        backend: backend.clone(),
                    });
                    for (n, path) in ibexwall_firewall::snapshot_paths(kind, &action, &default_zone)
                        .into_iter()
                        .enumerate()
                    {
                        let prior = match self.sys.fs.read(Path::new(&path)) {
                            Ok(content) => {
                                let meta = self.sys.fs.metadata(Path::new(&path))?;
                                let blob = format!("{index:03}-{n}.bin");
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
                            path,
                            prior,
                        });
                    }
                }
                // A one-way sysctl cannot be put back at runtime: the rollback
                // has no inverse for it (the plan said so), and must not fail
                // trying.
                Op::SysctlSet { key, value }
                    if ops::ONE_WAY_SYSCTLS.contains(&key.as_str()) && value != "0" =>
                {
                    entries.push(SnapshotEntry::NoInverse { op_index: index });
                }
                Op::SysctlSet { key, .. } => {
                    let prior = self.sys.sysctl.get(key).ok();
                    entries.push(SnapshotEntry::Sysctl {
                        op_index: index,
                        key: key.clone(),
                        prior,
                    });
                }
                Op::NftFragment { fragment } => {
                    let fragment = ibexwall_sys::ops::parse_fragment(fragment)?;
                    let chains = fragment
                        .chain_names()
                        .into_iter()
                        .map(|name| {
                            Ok(ibexwall_sys::ops::NftChainPrior {
                                prior: self.sys.nft.capture(&name)?,
                                name,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    entries.push(SnapshotEntry::Nft {
                        op_index: index,
                        chains,
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

    /// Writes the chains of our table, as they are now, to `file`, so they
    /// come back after a reboot (nftables keeps nothing across one).
    /// Atomic: a crash leaves the previous file or the new one.
    pub fn persist_nft(&self, file: &Path) -> Result<()> {
        if !self.sys.allow_system_executors {
            return Ok(());
        }
        let mut chains = serde_json::Map::new();
        for name in self.sys.nft.chains()? {
            if let Some(definition) = self.sys.nft.capture(&name)? {
                chains.insert(name, definition);
            }
        }
        if chains.is_empty() {
            return match std::fs::remove_file(file) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        let temporary = file.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(&chains)?)?;
        std::fs::rename(&temporary, file)?;
        Ok(())
    }

    /// Puts the persisted chains back, leaving alone any that already
    /// exist. Returns how many were restored.
    pub fn restore_nft(&self, file: &Path) -> Result<usize> {
        if !self.sys.allow_system_executors {
            return Ok(0);
        }
        let Ok(bytes) = std::fs::read(file) else {
            return Ok(0);
        };
        let chains: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes)?;
        let mut restored = 0;
        for (name, definition) in chains {
            if self.sys.nft.capture(&name)?.is_none() {
                self.sys.nft.restore(&name, Some(&definition))?;
                restored += 1;
            }
        }
        Ok(restored)
    }

    /// Executes ops in order. In production (root, systemd), file-touching
    /// transactions run inside the transient executor unit (ADR-0026);
    /// otherwise in-process (sandbox and tests).
    pub fn execute(&self, tx: Option<&str>, ops: &[Op]) -> Result<()> {
        if let Some(tx) = tx
            && self.sys.use_transient_executor
            && !ibexwall_sys::write_directories(ops).is_empty()
        {
            return self.execute_via_transient_unit(tx, ops);
        }
        for op in ops {
            ibexwall_sys::execute(op, &self.sys)
                .with_context(|| format!("executing {}", op_name(op)))?;
        }
        Ok(())
    }

    /// Writes the ops where the helper can read them and launches it in a
    /// transient unit with `ReadWritePaths` limited to this transaction.
    fn execute_via_transient_unit(&self, tx: &str, ops: &[Op]) -> Result<()> {
        use std::io::Write as _;
        let dirs = self.writable_ancestors(ibexwall_sys::write_directories(ops));
        let work = ibexwall_proto::names::runtime_dir()
            .join("executor")
            .join(tx);
        std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
        let ops_file = work.join("ops.json");
        let mut file = std::fs::File::create(&ops_file)?;
        file.write_all(&serde_json::to_vec(ops)?)?;
        drop(file);

        let exec_args = vec!["apply".to_string(), ops_file.to_string_lossy().into_owned()];
        self.sys
            .systemd
            .run_transient_executor(&format!("ibexwall-exec-{tx}-apply"), &exec_args, &dirs)
            .with_context(|| format!("starting the executor unit for {tx}"))?;
        Ok(())
    }

    /// The transient unit's ReadWritePaths must name directories that
    /// exist at unit start (its namespace is set up before the helper
    /// runs). A missing drop-in directory is represented by its nearest
    /// existing ancestor: the helper then creates the directory itself.
    fn writable_ancestors(&self, dirs: Vec<String>) -> Vec<String> {
        let mut resolved: std::collections::BTreeSet<String> = Default::default();
        for dir in dirs {
            let mut current = Path::new(&dir);
            loop {
                if self.sys.fs.exists(current) {
                    resolved.insert(current.to_string_lossy().into_owned());
                    break;
                }
                match current.parent() {
                    Some(parent) if parent != Path::new("/") => current = parent,
                    _ => {
                        // Nothing exists up the chain: give the whole root
                        // (the plan is about to fail honestly anyway).
                        resolved.insert("/".into());
                        break;
                    }
                }
            }
        }
        resolved.into_iter().collect()
    }

    /// Applies inverses in reverse order from the snapshot manifest.
    /// In production this runs inside the transient executor unit when
    /// the transaction needs it; the logic is shared with the helper.
    pub fn rollback(&self, state: &State, tx: &str) -> Result<()> {
        let bytes = std::fs::read(state.snapshots_dir().join(tx).join("manifest.json"))
            .with_context(|| format!("reading snapshot for {tx}"))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&bytes)?;
        if !self.sys.use_transient_executor {
            return ibexwall_sys::apply_snapshot_inverses(
                &self.sys,
                state.snapshots_dir(),
                &manifest,
            );
        }
        // The daemon unit cannot write /etc: the inverses also run inside
        // the transient executor, with the snapshot's own directories.
        let dirs = self.writable_ancestors(snapshot_write_directories(&manifest));
        let exec_args = vec![
            "rollback".to_string(),
            state
                .snapshots_dir()
                .join(tx)
                .to_string_lossy()
                .into_owned(),
        ];
        self.sys
            .systemd
            .run_transient_executor(&format!("ibexwall-exec-{tx}-rollback"), &exec_args, &dirs)
            .with_context(|| format!("starting the rollback executor unit for {tx}"))?;
        Ok(())
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Parent directories the inverses of a snapshot will write to.
fn snapshot_write_directories(manifest: &SnapshotManifest) -> Vec<String> {
    let mut dirs: std::collections::BTreeSet<String> = Default::default();
    for entry in &manifest.entries {
        match entry {
            SnapshotEntry::File { path, .. } => {
                if let Some(parent) = Path::new(path).parent() {
                    let parent = parent.to_string_lossy();
                    if !parent.is_empty() {
                        dirs.insert(parent.into_owned());
                    }
                }
            }
            // Putting a unit's enablement back may go through the SysV helper.
            SnapshotEntry::Unit { .. } => {
                dirs.extend(ibexwall_sys::ops::sysv_rc_directories());
            }
            // ufw's reload takes the xtables lock under /run.
            SnapshotEntry::Firewall { backend, .. } => {
                for path in ibexwall_sys::ops::firewall_write_paths(backend) {
                    dirs.insert(path);
                }
            }
            _ => {}
        }
    }
    dirs.into_iter().collect()
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
        Op::NftFragment { fragment } => ibexwall_sys::ops::parse_fragment(fragment)
            .map(|f| f.chain_names().join(", "))
            .unwrap_or_else(|_| "fragment".into()),
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
    use ibexwall_proto::UnitAction;
    use ibexwall_sys::{
        Enabled, FakeClock, FakeFs, FakeNft, FakeSysctl, FakeSystemd, Fs, Nft, SysBundle, Sysctl,
        UnitSnapshot,
    };
    use serde_json::json;
    use std::path::Path;
    use std::sync::Arc;

    struct Rig {
        engine: Engine,
        fs: Arc<FakeFs>,
        systemd: Arc<FakeSystemd>,
        sysctl: Arc<FakeSysctl>,
        nft: Arc<FakeNft>,
        runner: Arc<ibexwall_sys::firewall::FakeRunner>,
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
        let nft = Arc::new(FakeNft::new());
        let runner = Arc::new(ibexwall_sys::firewall::FakeRunner::new());
        let engine = Engine::with(SysBundle {
            fs: fs.clone(),
            runner: runner.clone(),
            systemd: systemd.clone(),
            sysctl: sysctl.clone(),
            clock: Arc::new(FakeClock::new(1_793_534_400)),
            allow_system_executors: allow_system,
            nft: nft.clone(),
            use_transient_executor: false,
        });
        Rig {
            engine,
            fs,
            systemd,
            sysctl,
            nft,
            runner,
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
        rig.engine.execute(None, &ops).unwrap();
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"new\n");
        rig.engine.rollback(&rig.state, "tx1").unwrap();
        assert_eq!(rig.fs.read(Path::new(path)).unwrap(), b"old\n");
    }

    #[test]
    fn a_flatpak_network_block_is_undone_byte_for_byte() {
        let rig = rig("fp", false);
        let overrides = "/var/lib/flatpak/overrides";
        let mine = format!("{overrides}/org.example.Mine");
        let fresh = format!("{overrides}/org.example.Fresh");
        let before = b"[Context]\nshared=ipc;\nfilesystems=home;\n";
        rig.fs.seed(Path::new(&mine), before);
        let block = |app: &str| Op::FlatpakOverride {
            app_id: app.into(),
            args: vec!["--unshare=network".into()],
        };
        let ops = vec![block("org.example.Mine"), block("org.example.Fresh")];
        rig.engine.snapshot(&rig.state, "txf", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        assert_eq!(
            rig.fs.read(Path::new(&mine)).unwrap(),
            b"[Context]\nshared=ipc;!network;\nfilesystems=home;\n"
        );
        assert_eq!(
            rig.fs.read(Path::new(&fresh)).unwrap(),
            b"[Context]\nshared=!network;\n"
        );
        rig.engine.rollback(&rig.state, "txf").unwrap();
        // What the administrator had comes back exactly; what we created
        // is gone.
        assert_eq!(rig.fs.read(Path::new(&mine)).unwrap(), before);
        assert!(!rig.fs.exists(Path::new(&fresh)));
    }

    fn fw(backend: &str, action: serde_json::Value) -> Op {
        Op::FirewallAdapter {
            backend: backend.into(),
            action,
        }
    }

    #[test]
    fn a_firewalld_change_runs_the_fixed_argv_and_rolls_back_with_a_reload() {
        let rig = rig("fwd", true);
        let zone = "/etc/firewalld/zones/public.xml";
        let before = b"<zone>\n  <service name=\"ssh\"/>\n</zone>\n";
        rig.fs.seed(Path::new(zone), before);
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "allow_port", "port": 8080, "proto": "tcp"}),
        )];
        rig.engine.snapshot(&rig.state, "txw1", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        assert_eq!(
            rig.runner.calls(),
            vec![
                vec![
                    "/usr/bin/firewall-cmd",
                    "--permanent",
                    "--add-port=8080/tcp"
                ],
                vec!["/usr/bin/firewall-cmd", "--add-port=8080/tcp"],
            ]
        );
        // What firewalld itself would have written.
        rig.fs.seed(Path::new(zone), b"<zone>changed</zone>\n");
        rig.engine.rollback(&rig.state, "txw1").unwrap();
        assert_eq!(rig.fs.read(Path::new(zone)).unwrap(), before);
        assert_eq!(
            rig.runner.calls().last().unwrap(),
            &vec!["/usr/bin/firewall-cmd", "--reload"]
        );
    }

    #[test]
    fn a_default_zone_change_is_undone_with_the_conf_file_and_a_reload() {
        let rig = rig("fwdz", true);
        let conf = "/etc/firewalld/firewalld.conf";
        let before = b"DefaultZone=public\nLockdown=no\n";
        rig.fs.seed(Path::new(conf), before);
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "set_default_zone", "name": "home"}),
        )];
        rig.engine.snapshot(&rig.state, "txdz", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        assert_eq!(
            rig.runner.calls(),
            vec![vec!["/usr/bin/firewall-cmd", "--set-default-zone=home"]]
        );
        rig.fs
            .seed(Path::new(conf), b"DefaultZone=home\nLockdown=no\n");
        rig.engine.rollback(&rig.state, "txdz").unwrap();
        assert_eq!(rig.fs.read(Path::new(conf)).unwrap(), before);
        assert_eq!(
            rig.runner.calls().last().unwrap(),
            &vec!["/usr/bin/firewall-cmd", "--reload"]
        );
    }

    #[test]
    fn a_zone_file_that_did_not_exist_is_removed_by_rollback() {
        let rig = rig("fwn", true);
        let zone = "/etc/firewalld/zones/public.xml";
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "allow_service", "name": "http"}),
        )];
        rig.engine.snapshot(&rig.state, "txw2", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        rig.fs.seed(Path::new(zone), b"<zone/>");
        rig.engine.rollback(&rig.state, "txw2").unwrap();
        assert!(!rig.fs.exists(Path::new(zone)));
    }

    #[test]
    fn the_default_zone_comes_from_firewalld_conf() {
        let rig = rig("fwz", true);
        rig.fs.seed(
            Path::new("/etc/firewalld/firewalld.conf"),
            b"DefaultZone=FedoraWorkstation\n",
        );
        rig.fs.seed(
            Path::new("/etc/firewalld/zones/FedoraWorkstation.xml"),
            b"<zone/>",
        );
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "remove_port", "port": 1, "proto": "udp"}),
        )];
        let manifest = rig.engine.snapshot(&rig.state, "txw3", &ops).unwrap();
        let paths: Vec<_> = manifest
            .entries
            .iter()
            .filter_map(|entry| match entry {
                ibexwall_sys::ops::SnapshotEntry::File { path, prior, .. } => {
                    Some((path.clone(), prior.is_some()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            vec![(
                "/etc/firewalld/zones/FedoraWorkstation.xml".to_string(),
                true
            )]
        );
    }

    #[test]
    fn ufw_snapshots_both_rule_files_and_needs_its_directory_and_the_lock() {
        let rig = rig("ufw", true);
        rig.fs.seed(Path::new("/etc/ufw/user.rules"), b"v4\n");
        rig.fs.seed(Path::new("/etc/ufw/user6.rules"), b"v6\n");
        let ops = vec![fw(
            "ufw",
            serde_json::json!({"action": "allow_port", "port": 22, "proto": "tcp"}),
        )];
        let manifest = rig.engine.snapshot(&rig.state, "txu1", &ops).unwrap();
        assert_eq!(
            ibexwall_sys::write_directories(&ops),
            vec!["/etc/ufw".to_string(), "/run/xtables.lock".to_string()]
        );
        assert_eq!(
            snapshot_write_directories(&manifest),
            vec!["/etc/ufw".to_string(), "/run/xtables.lock".to_string()]
        );
        rig.engine.execute(None, &ops).unwrap();
        assert_eq!(
            rig.runner.calls(),
            vec![vec!["/usr/sbin/ufw", "allow", "22/tcp"]]
        );
        rig.fs.seed(Path::new("/etc/ufw/user.rules"), b"changed\n");
        rig.engine.rollback(&rig.state, "txu1").unwrap();
        assert_eq!(
            rig.fs.read(Path::new("/etc/ufw/user.rules")).unwrap(),
            b"v4\n"
        );
        assert_eq!(
            rig.runner.calls().last().unwrap(),
            &vec!["/usr/sbin/ufw", "reload"]
        );
    }

    #[test]
    fn a_sandbox_never_runs_a_firewall_tool() {
        let rig = rig("fws", false);
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "allow_port", "port": 1, "proto": "tcp"}),
        )];
        assert!(rig.engine.execute(None, &ops).is_err());
        assert!(rig.runner.calls().is_empty());
    }

    #[test]
    fn a_failing_tool_stops_the_op_and_names_it() {
        let rig = rig("fwf", true);
        *rig.runner.fail_on.lock().unwrap() = Some("--add-port".into());
        let ops = vec![fw(
            "firewalld",
            serde_json::json!({"action": "allow_port", "port": 9, "proto": "tcp"}),
        )];
        let error = rig.engine.execute(None, &ops).unwrap_err();
        assert!(format!("{error:#}").contains("firewall.adapter"));
    }

    #[test]
    fn nft_chains_survive_a_restart_through_the_persisted_file() {
        let rig = rig("nfp", true);
        let file = rig.dir.join("nft-active.json");
        // Nothing active: nothing to write, and a stale file is removed.
        std::fs::write(&file, b"{}").unwrap();
        rig.engine.persist_nft(&file).unwrap();
        assert!(!file.exists());

        let fragment = serde_json::json!({ "chains": [
            { "name": "net_firewall_input", "rules": [] },
            { "name": "net_dns_guard", "rules": [] },
        ] });
        rig.engine
            .execute(None, &[Op::NftFragment { fragment }])
            .unwrap();
        rig.engine.persist_nft(&file).unwrap();
        assert!(file.exists());

        // A reboot empties nftables; the file brings the chains back.
        rig.nft.restore("net_firewall_input", None).unwrap();
        rig.nft.restore("net_dns_guard", None).unwrap();
        assert_eq!(rig.engine.restore_nft(&file).unwrap(), 2);
        assert!(rig.nft.has("net_firewall_input") && rig.nft.has("net_dns_guard"));
        // Chains that are already there are left alone.
        assert_eq!(rig.engine.restore_nft(&file).unwrap(), 0);
        // No file, no problem.
        assert_eq!(
            rig.engine
                .restore_nft(&rig.dir.join("missing.json"))
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_sandbox_never_persists_or_restores_chains() {
        let rig = rig("nfs", false);
        let file = rig.dir.join("nft-active.json");
        rig.engine.persist_nft(&file).unwrap();
        assert!(!file.exists());
        std::fs::write(&file, b"{\"x\": {}}").unwrap();
        assert_eq!(rig.engine.restore_nft(&file).unwrap(), 0);
    }

    #[test]
    fn file_write_creating_a_file_is_undone_by_removal() {
        let rig = rig("fc", false);
        let path = "/etc/ibexwall-tests/new.conf";
        let ops = vec![write(path, "x\n")];
        rig.engine.snapshot(&rig.state, "tx2", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
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
        rig.engine.execute(None, &ops).unwrap();
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
        rig.engine.execute(None, &ops).unwrap();
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
            rig.engine.execute(None, &ops).unwrap();
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
    fn rolling_back_a_restart_does_not_touch_the_units_enablement() {
        // Ubuntu's ssh.service is "disabled" (its socket is what is
        // enabled); disabling it again would fail under the executor and
        // changes nothing the transaction did.
        let rig = rig("unit2", false);
        rig.systemd.seed(
            "ibexwall-test.service",
            UnitSnapshot {
                enabled: Enabled::Disabled,
                active: true,
            },
        );
        let ops = vec![Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: None,
        }];
        rig.engine.snapshot(&rig.state, "txu2", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        rig.engine.rollback(&rig.state, "txu2").unwrap();
        let log = rig.systemd.log.snapshot().join("\n");
        assert!(!log.contains("Disable"), "{log}");
        assert!(!log.contains("Enable"), "{log}");
        assert!(rig.systemd.get("ibexwall-test.service").active);
    }

    #[test]
    fn rolling_back_a_one_way_sysctl_does_not_try_to_undo_it() {
        let rig = rig("oneway", false);
        rig.sysctl.seed("kernel.kexec_load_disabled", "0");
        let ops = vec![Op::SysctlSet {
            key: "kernel.kexec_load_disabled".into(),
            value: "1".into(),
        }];
        rig.engine.snapshot(&rig.state, "txow", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        rig.engine.rollback(&rig.state, "txow").unwrap();
        // Nothing wrote the prior value back (the kernel would refuse).
        let log = rig.sysctl.log.snapshot();
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(log[0].contains("kexec_load_disabled = 1"));
    }

    fn nft_guard(rules: usize) -> Op {
        Op::NftFragment {
            fragment: json!({ "chains": [{
                "name": "dev_echo_guard",
                "rules": (0..rules).map(|_| json!({ "verdict": "accept" })).collect::<Vec<_>>(),
            }] }),
        }
    }

    #[test]
    fn a_new_nft_chain_is_removed_by_rollback() {
        let rig = rig("nft1", true);
        let ops = vec![nft_guard(2)];
        rig.engine.snapshot(&rig.state, "txn1", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        assert!(rig.nft.has("dev_echo_guard"));
        rig.engine.rollback(&rig.state, "txn1").unwrap();
        assert!(!rig.nft.has("dev_echo_guard"));
    }

    #[test]
    fn an_existing_nft_chain_is_restored_as_it_was() {
        let rig = rig("nft2", true);
        let first = vec![nft_guard(1)];
        rig.engine.snapshot(&rig.state, "txa", &first).unwrap();
        rig.engine.execute(None, &first).unwrap();
        let before = rig.nft.capture("dev_echo_guard").unwrap();

        let second = vec![nft_guard(5)];
        rig.engine.snapshot(&rig.state, "txb", &second).unwrap();
        rig.engine.execute(None, &second).unwrap();
        assert_ne!(rig.nft.capture("dev_echo_guard").unwrap(), before);
        rig.engine.rollback(&rig.state, "txb").unwrap();
        assert_eq!(rig.nft.capture("dev_echo_guard").unwrap(), before);
    }

    #[test]
    fn nft_is_refused_without_system_executors() {
        let rig = rig("nft3", false);
        assert!(rig.engine.execute(None, &[nft_guard(1)]).is_err());
        assert!(!rig.nft.has("dev_echo_guard"));
    }

    #[test]
    fn a_restarted_unit_is_restarted_again_after_files_are_restored() {
        // A service that reads a config file must reload the restored
        // content: the restart goes after the file inverses, not before.
        let rig = rig("rs", false);
        rig.systemd.seed(
            "ibexwall-test.service",
            UnitSnapshot {
                enabled: Enabled::Enabled,
                active: true,
            },
        );
        let ops = vec![
            Op::FileWrite {
                path: "/etc/ibexwall-tests/a.conf".into(),
                content: "new\n".into(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SystemdUnit {
                unit: "ibexwall-test.service".into(),
                action: UnitAction::Restart,
                now: None,
            },
        ];
        rig.engine.snapshot(&rig.state, "txr", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        let before = rig.systemd.log.len();
        rig.engine.rollback(&rig.state, "txr").unwrap();
        let during_rollback = rig.systemd.log.snapshot()[before..].to_vec();
        assert_eq!(
            during_rollback.last().map(String::as_str),
            Some("Restart ibexwall-test.service now=false"),
            "{during_rollback:?}"
        );
    }

    #[test]
    fn a_unit_that_was_stopped_is_not_restarted_by_rollback() {
        let rig = rig("rs2", false);
        rig.systemd.seed(
            "ibexwall-test.service",
            UnitSnapshot {
                enabled: Enabled::Enabled,
                active: false,
            },
        );
        let ops = vec![Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: None,
        }];
        rig.engine.snapshot(&rig.state, "txr2", &ops).unwrap();
        rig.engine.execute(None, &ops).unwrap();
        let before = rig.systemd.log.len();
        rig.engine.rollback(&rig.state, "txr2").unwrap();
        let during = rig.systemd.log.snapshot()[before..].to_vec();
        assert!(
            !during.iter().any(|e| e.starts_with("Restart")),
            "{during:?}"
        );
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
        rig.engine.execute(None, &ops).unwrap();
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
        assert!(rig.engine.execute(None, &ops).is_err());
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
                fragment: json!({ "chains": [{ "name": "dev_echo_c", "rules": [] }] }),
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
        let sandboxed = ibexwall_sys::SysBundle::real_under(Path::new("/tmp/some-root"));
        assert!(!sandboxed.allow_system_executors);
    }
}
