// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! System interaction traits (the testability seam): every effect the
//! core can have on the machine goes through one of these traits, with
//! a real implementation (argv only, no shell) and a recording fake for
//! unprivileged tests under `IBEXWALL_ROOT`.
//!
//! F1 scope: Fs, Systemd, Sysctl, Polkit, Clock, Identity. More
//! backends (Nft, Flatpak, Snap, NetworkManager...) land with their
//! phases.

pub mod browser;
pub mod clock;
pub mod firewall;
pub mod flatpak;
pub mod fs;
pub mod identity;
pub mod ops;
pub mod tls;
pub use ops::{
    OpError, PriorFile, SnapshotEntry, SnapshotManifest, apply_snapshot_inverses, execute,
    group_id, ops_digest, write_directories,
};

use std::sync::Arc;

/// System bundle the engine executes against; fakes for tests.
pub struct SysBundle {
    pub fs: Arc<dyn Fs>,
    /// Runs the allowlisted firewall tools (ADR-0034).
    pub runner: Arc<dyn firewall::Runner>,
    pub systemd: Arc<dyn Systemd>,
    pub sysctl: Arc<dyn Sysctl>,
    pub clock: Arc<dyn Clock>,
    pub nft: Arc<dyn Nft>,
    /// System-level executors (nft, exec, package installs) are refused
    /// while running under `IBEXWALL_ROOT` so the dev host is never
    /// touched.
    pub allow_system_executors: bool,
    /// Production mode: file-touching transactions run inside the
    /// transient executor unit (ADR-0026). False under a sandbox root
    /// and in tests with fakes.
    pub use_transient_executor: bool,
    /// Where the executor work directory lives. Production leaves it
    /// None (the real `/run/ibexwall`, a tmpfs, so a plan's secrets
    /// never reach disk); tests point it at a temp directory so nothing
    /// ever touches `/run` on the developer's machine.
    pub executor_work_dir: Option<std::path::PathBuf>,
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
            runner: Arc::new(firewall::RealRunner),
            systemd: Arc::new(RealSystemd::new()),
            sysctl: Arc::new(RealSysctl::with_root(root.to_path_buf())),
            clock: Arc::new(RealClock),
            // Real nftables only on the real root; a sandbox never applies
            // rules (system executors are refused there).
            nft: if real_root {
                Arc::new(RealNft)
            } else {
                Arc::new(FakeNft::new())
            },
            allow_system_executors: real_root,
            use_transient_executor: real_root,
            executor_work_dir: None,
        }
    }
}

pub mod nft;
pub mod nm;
pub mod polkit;
pub mod sysctl;
pub mod systemd;

pub use browser::{TARGETS, doh_off, is_ours, target};
pub use clock::{Clock, FakeClock, RealClock, format_rfc3339};
pub use fs::{FakeFs, FileMeta, Fs, RealFs};
pub use identity::{Identity, current_uid, peer_credentials, proc_start_time};
pub use nft::{FakeNft, Fragment, Nft, RealNft};
pub use polkit::{Decision, FakePolkit, Polkit, RealPolkit};
pub use sysctl::{FakeSysctl, RealSysctl, Sysctl};
pub use systemd::{Enabled, FakeSystemd, RealSystemd, Systemd, UnitSnapshot};

/// Records of what a fake was asked to do (for assertions).
pub mod log {
    use std::sync::Mutex;

    /// A thread-safe ordered log of operation descriptions.
    #[derive(Debug, Default)]
    pub struct OpLog {
        entries: Mutex<Vec<String>>,
    }

    impl OpLog {
        pub fn push(&self, entry: String) {
            self.entries.lock().expect("lock poisoned").push(entry);
        }

        pub fn snapshot(&self) -> Vec<String> {
            self.entries.lock().expect("lock poisoned").clone()
        }

        pub fn is_empty(&self) -> bool {
            self.entries.lock().expect("lock poisoned").is_empty()
        }

        pub fn len(&self) -> usize {
            self.entries.lock().expect("lock poisoned").len()
        }
    }
}
