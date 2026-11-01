// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! systemd unit control. The real implementation shells out to
//! `systemctl` with fixed argv (never a shell, never interpolation).

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;

use ibexwall_proto::UnitAction;
use serde::{Deserialize, Serialize};

use crate::log::OpLog;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enabled {
    Enabled,
    Disabled,
    Masked,
    Static,
    NotFound,
}

/// Unit state needed for snapshots and inverse operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSnapshot {
    pub enabled: Enabled,
    pub active: bool,
}

impl Default for UnitSnapshot {
    fn default() -> Self {
        Self {
            enabled: Enabled::NotFound,
            active: false,
        }
    }
}

pub trait Systemd: Send + Sync {
    fn snapshot(&self, unit: &str) -> anyhow::Result<UnitSnapshot>;
    fn apply(&self, unit: &str, action: UnitAction, now: bool) -> anyhow::Result<()>;
}

/// Real systemd control via `systemctl`. Disabled under a sandbox root:
/// unit operations would affect the dev host.
#[derive(Debug, Clone)]
pub struct RealSystemd {
    enabled: bool,
}

impl Default for RealSystemd {
    fn default() -> Self {
        Self {
            enabled: ibexwall_proto::names::root() == std::path::Path::new("/"),
        }
    }
}

impl RealSystemd {
    pub fn new() -> Self {
        Self::default()
    }
}

fn systemctl(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("systemctl").args(args).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "systemctl {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl Systemd for RealSystemd {
    fn snapshot(&self, unit: &str) -> anyhow::Result<UnitSnapshot> {
        anyhow::ensure!(
            self.enabled,
            "systemd control is disabled under IBEXWALL_ROOT"
        );
        let enabled = match systemctl(&["is-enabled", unit]) {
            Ok(text) => match text.trim() {
                "enabled" => Enabled::Enabled,
                "disabled" => Enabled::Disabled,
                "masked" => Enabled::Masked,
                "static" | "alias" | "indirect" => Enabled::Static,
                other => anyhow::bail!("unexpected is-enabled output for {unit}: {other}"),
            },
            Err(_) => Enabled::NotFound,
        };
        let active = systemctl(&["is-active", "--quiet", unit])
            .map(|_| true)
            .unwrap_or(false);
        Ok(UnitSnapshot { enabled, active })
    }

    fn apply(&self, unit: &str, action: UnitAction, now: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.enabled,
            "systemd control is disabled under IBEXWALL_ROOT"
        );
        let verb = match action {
            UnitAction::Start => "start",
            UnitAction::Stop => "stop",
            UnitAction::Restart => "restart",
            UnitAction::Enable => "enable",
            UnitAction::Disable => "disable",
            UnitAction::Mask => "mask",
            UnitAction::Unmask => "unmask",
        };
        let mut args: Vec<&str> = vec![verb];
        if now && matches!(action, UnitAction::Enable | UnitAction::Disable) {
            args.push("--now");
        }
        args.push(unit);
        systemctl(&args)?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FakeSystemd {
    units: Mutex<BTreeMap<String, UnitSnapshot>>,
    pub log: OpLog,
}

impl FakeSystemd {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, unit: &str, snapshot: UnitSnapshot) {
        self.units.lock().unwrap().insert(unit.into(), snapshot);
    }

    pub fn get(&self, unit: &str) -> UnitSnapshot {
        self.units
            .lock()
            .unwrap()
            .get(unit)
            .copied()
            .unwrap_or_default()
    }
}

impl Systemd for FakeSystemd {
    fn snapshot(&self, unit: &str) -> anyhow::Result<UnitSnapshot> {
        Ok(self.get(unit))
    }

    fn apply(&self, unit: &str, action: UnitAction, now: bool) -> anyhow::Result<()> {
        self.log.push(format!("{action:?} {unit} now={now}"));
        let mut units = self.units.lock().unwrap();
        let snapshot = units.entry(unit.into()).or_default();
        match action {
            UnitAction::Start => snapshot.active = true,
            UnitAction::Stop => snapshot.active = false,
            UnitAction::Restart => snapshot.active = true,
            UnitAction::Enable => {
                snapshot.enabled = Enabled::Enabled;
                if now {
                    snapshot.active = true;
                }
            }
            UnitAction::Disable => {
                snapshot.enabled = Enabled::Disabled;
                if now {
                    snapshot.active = false;
                }
            }
            UnitAction::Mask => snapshot.enabled = Enabled::Masked,
            UnitAction::Unmask => snapshot.enabled = Enabled::Disabled,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_systemd_tracks_state_and_logs() {
        let fake = FakeSystemd::new();
        fake.seed(
            "chronyd.service",
            UnitSnapshot {
                enabled: Enabled::Enabled,
                active: false,
            },
        );
        fake.apply("chronyd.service", UnitAction::Start, false)
            .unwrap();
        assert!(fake.snapshot("chronyd.service").unwrap().active);
        fake.apply("chronyd.service", UnitAction::Disable, true)
            .unwrap();
        let snapshot = fake.snapshot("chronyd.service").unwrap();
        assert_eq!(snapshot.enabled, Enabled::Disabled);
        assert!(!snapshot.active);
        assert_eq!(fake.log.len(), 2);
    }

    #[test]
    fn unknown_unit_defaults_to_not_found() {
        let fake = FakeSystemd::new();
        let snapshot = fake.snapshot("nope.service").unwrap();
        assert_eq!(snapshot.enabled, Enabled::NotFound);
        assert!(!snapshot.active);
    }
}
