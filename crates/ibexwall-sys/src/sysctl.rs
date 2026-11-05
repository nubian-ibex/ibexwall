// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! sysctl access. The real implementation reads and writes
//! `<root>/proc/sys/<key with '/' instead of '.'>` so tests can point it
//! at a sandbox tree via `IBEXWALL_ROOT` (paths come from
//! `ibexwall_proto::names`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use ibexwall_proto::names;

use crate::log::OpLog;

pub trait Sysctl: Send + Sync {
    fn get(&self, key: &str) -> anyhow::Result<String>;
    fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub struct RealSysctl {
    /// Root override for tests; defaults to `names::root()`.
    root: PathBuf,
}

impl Default for RealSysctl {
    fn default() -> Self {
        Self {
            root: names::root(),
        }
    }
}

impl RealSysctl {
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, key: &str) -> PathBuf {
        let relative = key.replace('.', "/");
        self.root.join("proc/sys").join(relative)
    }
}

impl Sysctl for RealSysctl {
    fn get(&self, key: &str) -> anyhow::Result<String> {
        let value = std::fs::read_to_string(self.path(key))?;
        Ok(value.trim().to_string())
    }

    fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        std::fs::write(self.path(key), value)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FakeSysctl {
    values: Mutex<BTreeMap<String, String>>,
    pub log: OpLog,
}

impl FakeSysctl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, key: &str, value: &str) {
        self.values
            .lock()
            .expect("lock poisoned")
            .insert(key.into(), value.into());
    }
}

impl Sysctl for FakeSysctl {
    fn get(&self, key: &str) -> anyhow::Result<String> {
        self.values
            .lock()
            .expect("lock poisoned")
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("sysctl {key}: not found"))
    }

    fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.log.push(format!("set {key} = {value}"));
        self.values
            .lock()
            .expect("lock poisoned")
            .insert(key.into(), value.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_sysctl_roundtrip_under_a_test_root() {
        let root = std::env::temp_dir().join(format!("ibexwall-sys-sysctl-{}", std::process::id()));
        let dir = root.join("proc/sys/kernel");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ibexwall_test"), "0\n").unwrap();

        let sysctl = RealSysctl::with_root(root.clone());
        assert_eq!(sysctl.get("kernel.ibexwall_test").unwrap(), "0");
        sysctl.set("kernel.ibexwall_test", "1").unwrap();
        assert_eq!(sysctl.get("kernel.ibexwall_test").unwrap(), "1");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fake_sysctl_records_sets() {
        let fake = FakeSysctl::new();
        fake.seed("kernel.kptr_restrict", "1");
        assert_eq!(fake.get("kernel.kptr_restrict").unwrap(), "1");
        fake.set("kernel.kptr_restrict", "2").unwrap();
        assert_eq!(fake.get("kernel.kptr_restrict").unwrap(), "2");
        assert_eq!(fake.log.snapshot(), vec!["set kernel.kptr_restrict = 2"]);
    }
}
