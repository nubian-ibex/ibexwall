// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The change engine (spec §4.5): validation gate, snapshots, ordered
//! execution, inverses for rollback, and the confirm-window state
//! machine. Synchronous by design; the API layer runs it in blocking
//! tasks. Highest coverage target in the project (>= 90%).

pub mod ops;

use std::path::{Path, PathBuf};

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
    pub fn snapshot(
        &self,
        state: &State,
        tx: &str,
        ops: &[Op],
        reload_execs: &[(String, Vec<String>)],
    ) -> Result<SnapshotManifest> {
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
                            durable_write(&dir.join("files").join(&blob), &content)?;
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
                            durable_write(&dir.join("files").join(&blob), &content)?;
                            Some(PriorFile {
                                sha256: hex::encode(sha2::Sha256::digest(&content)),
                                blob,
                                mode: meta.mode,
                                uid: meta.uid,
                                gid: meta.gid,
                            })
                        }
                        Ok(_) => None,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => {
                            return Err(
                                anyhow::Error::new(e).context(format!("snapshotting {path}"))
                            );
                        }
                    };
                    entries.push(SnapshotEntry::File {
                        op_index: index,
                        path: path.into(),
                        prior,
                    });
                }
                Op::TlsKeyPair {
                    cert_path,
                    key_path,
                    ..
                } => {
                    // Both files, so a rollback puts back the old pair or
                    // leaves none.
                    for (n, path) in [cert_path, key_path].into_iter().enumerate() {
                        let prior = match self.sys.fs.read(Path::new(path)) {
                            Ok(content) => {
                                let meta = self.sys.fs.metadata(Path::new(path))?;
                                let blob = format!("{index:03}-{n}.bin");
                                durable_write(&dir.join("files").join(&blob), &content)?;
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
                                durable_write(&dir.join("files").join(&blob), &content)?;
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
                    let prior = match self.sys.sysctl.get(key) {
                        Ok(value) => Some(value),
                        // A key this kernel does not have is genuinely
                        // absent; anything else is a read failure that
                        // must not silently lose the prior value.
                        Err(e)
                            if e.downcast_ref::<std::io::Error>()
                                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                        {
                            None
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "reading sysctl {key} for the snapshot: {e:#}"
                            ));
                        }
                    };
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
                Op::Exec { path, args }
                    if reload_execs.iter().any(|(p, a)| p == path && a == args) =>
                {
                    entries.push(SnapshotEntry::Reload {
                        op_index: index,
                        exec: ibexwall_sys::ops::ReloadExec {
                            path: path.clone(),
                            args: args.clone(),
                        },
                    });
                }
                _ => entries.push(SnapshotEntry::NoInverse { op_index: index }),
            }
        }
        let manifest = SnapshotManifest {
            tx: tx.to_string(),
            entries,
        };
        // Crash-safety order: blobs are synced as written, then the files
        // directory, then the manifest, then the snapshot directory, so a
        // manifest never names a blob that is not durable yet.
        sync_dir(&dir.join("files"))?;
        durable_write(
            &dir.join("manifest.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        sync_dir(&dir)?;
        Ok(manifest)
    }

    /// Writes the chains of our table, as they are now, to `file`, so they
    /// come back after a reboot (nftables keeps nothing across one).
    /// Atomic: a crash leaves the previous file or the new one.
    pub fn persist_nft(&self, file: &Path) -> Result<()> {
        if !self.sys.allow_system_executors {
            return Ok(());
        }
        // One writer at a time: apply, the confirm watchdog and the Ask
        // reconciler all land here, and a shared `.tmp` name would let
        // them truncate each other.
        static PERSIST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = PERSIST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut chains = serde_json::Map::new();
        for name in self.sys.nft.chains()? {
            if let Some(definition) = self.sys.nft.capture(&name)? {
                chains.insert(name, definition);
            }
        }
        let file = under_root(file);
        if chains.is_empty() {
            return match self.sys.fs.remove(&file) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        self.sys
            .fs
            .write_atomic(&file, &serde_json::to_vec_pretty(&chains)?, 0o600, None)?;
        Ok(())
    }

    /// Removes every chain left in IbexWall's table (the uninstall); returns
    /// how many there were. The foreign tables are never looked at.
    pub fn remove_nft_table(&self) -> Result<usize> {
        if !self.sys.allow_system_executors {
            return Ok(0);
        }
        let chains = self.sys.nft.chains()?;
        for name in &chains {
            self.sys.nft.restore(name, None)?;
        }
        Ok(chains.len())
    }

    /// Puts the persisted chains back, leaving alone any that already
    /// exist. Returns how many were restored.
    pub fn restore_nft(&self, file: &Path) -> Result<usize> {
        if !self.sys.allow_system_executors {
            return Ok(0);
        }
        // A missing file is normal (nothing persisted yet); anything else
        // (unreadable, a broken disk) must stop the boot path instead of
        // reading as "nothing to restore".
        let bytes = match self.sys.fs.read(&under_root(file)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
            Ok(bytes) => bytes,
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
    /// The ops can hold secrets (a VPN profile's private key), so the
    /// work directory is private to the daemon and removed when the run
    /// ends.
    fn execute_via_transient_unit(&self, tx: &str, ops: &[Op]) -> Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dirs = self.writable_ancestors(ibexwall_sys::write_directories(ops));
        let base = self
            .sys
            .executor_work_dir
            .clone()
            .unwrap_or_else(ibexwall_proto::names::runtime_dir);
        let work = base.join("executor").join(tx);
        std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("closing {}", work.display()))?;
        let ops_file = work.join("ops.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ops_file)?;
        file.write_all(&serde_json::to_vec(ops)?)?;
        drop(file);

        let exec_args = vec!["apply".to_string(), ops_file.to_string_lossy().into_owned()];
        let run = self.sys.systemd.run_transient_executor(
            &format!("ibexwall-exec-{tx}-apply"),
            &exec_args,
            &dirs,
        );
        // Secrets must not outlive the run, not even until the next boot
        // (`RuntimeDirectoryPreserve=yes` keeps /run/ibexwall).
        if let Err(error) = std::fs::remove_dir_all(&work)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %error, "removing the executor work dir failed");
        }
        run.with_context(|| format!("starting the executor unit for {tx}"))?;
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
/// Writes and fsyncs a snapshot file: the prior content must be on disk
/// before the manifest that names it, or a crash could leave a change on
/// the machine with an unrestorable snapshot.
fn durable_write(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// fsyncs a directory so its entries are durable.
fn sync_dir(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// `Core` builds its paths already prefixed with the sandbox root when
/// one is active, while the `SysBundle` filesystem translates under its
/// own root: strip the prefix here so the two never double up.
fn under_root(path: &Path) -> PathBuf {
    let root = ibexwall_proto::names::root();
    if root == Path::new("/") {
        return path.to_path_buf();
    }
    match path.strip_prefix(&root) {
        Ok(rest) => Path::new("/").join(rest),
        Err(_) => path.to_path_buf(),
    }
}

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
        Op::TlsKeyPair { .. } => "tls.keypair",
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
        Op::TlsKeyPair { cert_path, .. } => cert_path.clone(),
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
        // A file only its owner can read (a VPN key) is not printed into
        // previews, proposals or logs.
        Op::FileWrite { content, mode, .. }
            if u32::from_str_radix(mode, 8).is_ok_and(|m| m & 0o077 == 0) =>
        {
            Some(format!(
                "+(private file, {} lines hidden)",
                content.lines().count()
            ))
        }
        Op::FileWrite { content, .. } => Some(
            content
                .lines()
                .map(|line| format!("+{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Op::FileRemove { .. } => Some(format!("-{index:03}: file removed")),
        // The key does not exist yet, and when it does it is shown nowhere.
        Op::TlsKeyPair { hosts, days, .. } => Some(format!(
            "+(a new certificate for {} valid {days} days, and its private key, made when this is applied and never shown)",
            hosts.join(", ")
        )),
        _ => None,
    }
}

/// Aggregated flags helper used by the API layer.
pub fn flags_from(ops: &[Op]) -> Vec<RiskFlag> {
    ops::risk_flags(ops)
}

#[cfg(test)]
mod tests;
