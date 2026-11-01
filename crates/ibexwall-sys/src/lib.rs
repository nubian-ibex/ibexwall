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

pub mod clock;
pub mod fs;
pub mod identity;
pub mod polkit;
pub mod sysctl;
pub mod systemd;

pub use clock::{format_rfc3339, Clock, FakeClock, RealClock};
pub use fs::{FakeFs, FileMeta, Fs, RealFs};
pub use identity::{Identity, peer_credentials, proc_start_time};
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
            self.entries.lock().unwrap().push(entry);
        }

        pub fn snapshot(&self) -> Vec<String> {
            self.entries.lock().unwrap().clone()
        }

        pub fn is_empty(&self) -> bool {
            self.entries.lock().unwrap().is_empty()
        }

        pub fn len(&self) -> usize {
            self.entries.lock().unwrap().len()
        }
    }
}
