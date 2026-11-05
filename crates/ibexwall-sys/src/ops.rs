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
    /// A firewall manager whose files a firewall.adapter op changes:
    /// after the files are restored it is told to re-read them.
    Firewall { op_index: usize, backend: String },
    /// Ops without a system inverse (exec).
    NoInverse { op_index: usize },
    /// A symmetric exec the manifest declared: re-run in the rollback's
    /// second pass, after the files are restored.
    Reload {
        op_index: usize,
        #[serde(flatten)]
        exec: ReloadExec,
    },
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

/// An allowlisted exec that is its own inverse, re-run by the rollback
/// after the files are restored (a manager told to re-read its directory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadExec {
    pub path: String,
    pub args: Vec<String>,
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
            // ufw rewrites its own files and takes the xtables lock; the
            // executor unit needs both (its /run is read-only otherwise).
            Op::FirewallAdapter { backend, .. } if backend == "ufw" => {
                for path in firewall_write_paths("ufw") {
                    dirs.insert(path);
                }
                continue;
            }
            // `systemctl enable` and `disable` hand units that also ship a
            // SysV script to `systemd-sysv-install` (update-rc.d on Debian
            // and Ubuntu), and that client-side helper rewrites the rc
            // symlinks itself. Only directories that exist are opened.
            Op::SystemdUnit {
                action: ibexwall_proto::UnitAction::Enable | ibexwall_proto::UnitAction::Disable,
                ..
            } => {
                dirs.extend(sysv_rc_directories());
                continue;
            }
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

/// The SysV runlevel directories that exist on this machine (Debian and
/// Ubuntu): where `systemd-sysv-install` rewrites symlinks when a unit that
/// also ships an init script is enabled or disabled.
pub fn sysv_rc_directories() -> Vec<String> {
    ["0", "1", "2", "3", "4", "5", "6", "S"]
        .iter()
        .map(|level| format!("/etc/rc{level}.d"))
        .filter(|dir| Path::new(dir).is_dir())
        .collect()
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
        Op::FirewallAdapter { backend, action } => {
            if !sys.allow_system_executors {
                return Err(OpError::SandboxBlocked.into());
            }
            let (backend, action) = parse_firewall(backend, action)?;
            for argv in ibexwall_firewall::argv(backend, &action) {
                sys.runner.run(&argv)?;
            }
            Ok(())
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

/// What a `firewall.adapter` op must be, or why it is refused.
pub fn parse_firewall(
    backend: &str,
    action: &serde_json::Value,
) -> Result<(
    ibexwall_firewall::Backend,
    ibexwall_firewall::FirewallAction,
)> {
    let backend =
        ibexwall_firewall::Backend::from_name(backend).ok_or_else(|| OpError::Invalid {
            field: "firewall.adapter",
            reason: format!("unknown backend `{backend}`"),
        })?;
    let action: ibexwall_firewall::FirewallAction = serde_json::from_value(action.clone())
        .map_err(|e| OpError::Invalid {
            field: "firewall.adapter",
            reason: e.to_string(),
        })?;
    ibexwall_firewall::validate(backend, &action).map_err(|e| OpError::Invalid {
        field: "firewall.adapter",
        reason: e.to_string(),
    })?;
    Ok((backend, action))
}

/// The paths a manager's tool needs to write, for the executor unit.
pub fn firewall_write_paths(backend: &str) -> Vec<String> {
    match backend {
        "ufw" => vec!["/etc/ufw".into(), "/run/xtables.lock".into()],
        _ => vec![],
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

/// Groups IbexWall itself creates (packaging/sysusers.d) that a file may be
/// given by name: the assistants' group reads the MCP access settings. Any
/// other name is refused, so an op cannot hand a file to a group of its choice.
const NAMED_GROUPS: &[&str] = &["ibexwall-assistants", "ibexwall-mcp"];

fn gid_in(group_file: &str, name: &str) -> Option<u32> {
    group_file.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

fn resolve_group(group: &str) -> Result<u32> {
    match group {
        "root" => Ok(0),
        named if NAMED_GROUPS.contains(&named) => {
            let file = std::fs::read_to_string("/etc/group").unwrap_or_default();
            Ok(gid_in(&file, named).ok_or_else(|| OpError::Invalid {
                field: "group",
                reason: format!("`{named}` does not exist on this machine"),
            })?)
        }
        numeric => Ok(numeric.parse::<u32>().map_err(|_| OpError::Invalid {
            field: "group",
            reason: format!("`{group}`: `root`, one of IbexWall's own groups, or a numeric gid"),
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
                // Put back only what the transaction changed: touching the
                // enablement of a unit that was merely restarted would fail
                // on units whose enablement the init scripts own (Ubuntu's
                // `ssh.service`, with its socket) and gains nothing.
                let now = sys.systemd.snapshot(unit)?;
                let enable_differs = now.enabled != enabled;
                match enabled {
                    crate::Enabled::Enabled if enable_differs => {
                        sys.systemd.apply(unit, UnitAction::Enable, false)?;
                    }
                    crate::Enabled::Disabled if enable_differs => {
                        sys.systemd.apply(unit, UnitAction::Disable, false)?;
                    }
                    crate::Enabled::Masked if enable_differs => {
                        sys.systemd.apply(unit, UnitAction::Stop, false)?;
                        sys.systemd.apply(unit, UnitAction::Mask, false)?;
                    }
                    _ => {}
                }
                if now.active != *active {
                    let action = if *active {
                        UnitAction::Start
                    } else {
                        UnitAction::Stop
                    };
                    sys.systemd.apply(unit, action, false)?;
                }
            }
            SnapshotEntry::Sysctl { key, prior, .. } => {
                if let Some(value) = prior {
                    sys.sysctl
                        .set(key, value)
                        .with_context(|| format!("restoring sysctl {key} = {value}"))?;
                }
            }
            SnapshotEntry::Nft { chains, .. } => {
                for chain in chains {
                    sys.nft.restore(&chain.name, chain.prior.as_ref())?;
                }
            }
            SnapshotEntry::Reload { exec, .. } => {
                execute(
                    &Op::Exec {
                        path: exec.path.clone(),
                        args: exec.args.clone(),
                    },
                    sys,
                )
                .with_context(|| format!("re-running {} {}", exec.path, exec.args.join(" ")))?;
            }
            SnapshotEntry::Firewall { .. } | SnapshotEntry::NoInverse { .. } => {}
        }
    }
    // Second pass: services restarted by the transaction pick up the
    // restored files. Only units that were running before are restarted;
    // a stopped one was already stopped by the first pass.
    for entry in &manifest.entries {
        match entry {
            SnapshotEntry::Unit {
                unit,
                active: true,
                restarted: true,
                ..
            } => sys.systemd.apply(unit, UnitAction::Restart, false)?,
            // After the restored files: the manager re-reads its directory
            // and lets go of what the transaction created or removed.
            SnapshotEntry::Reload { exec, .. } => {
                execute(
                    &Op::Exec {
                        path: exec.path.clone(),
                        args: exec.args.clone(),
                    },
                    sys,
                )
                .with_context(|| format!("re-running {} {}", exec.path, exec.args.join(" ")))?;
            }
            // The restored files are on disk: make the manager read them.
            SnapshotEntry::Firewall { backend, .. } => {
                if let Some(backend) = ibexwall_firewall::Backend::from_name(backend)
                    && let Some(argv) = ibexwall_firewall::reload_argv(backend)
                {
                    sys.runner.run(&argv)?;
                }
            }
            _ => {}
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
    #[test]
    fn only_root_numbers_and_ibexwalls_own_groups_can_own_a_file() {
        let groups = "root:x:0:\nibexwall-assistants:x:981:ana,bob\nwheel:x:10:\n";
        assert_eq!(gid_in(groups, "ibexwall-assistants"), Some(981));
        assert_eq!(gid_in(groups, "ibexwall-mcp"), None);
        assert_eq!(resolve_group("root").unwrap(), 0);
        assert_eq!(resolve_group("42").unwrap(), 42);
        // A named group outside the list is refused, whatever exists on disk.
        for refused in ["wheel", "shadow", "sudo", "ibexwall-assistants2", ""] {
            assert!(resolve_group(refused).is_err(), "{refused}");
        }
    }

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
