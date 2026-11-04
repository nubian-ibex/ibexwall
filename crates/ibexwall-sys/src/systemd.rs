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
    /// Runs the executor helper for one transaction in a transient unit
    /// (ADR-0026): `ReadWritePaths` limited to `dirs`, hardened like the
    /// daemon, and the call blocks until the unit finishes.
    fn run_transient_executor(
        &self,
        unit: &str,
        exec_args: &[String],
        dirs: &[String],
    ) -> anyhow::Result<()>;
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

/// Maps the text of `systemctl is-enabled` (documented in systemctl(1)) to
/// a state. An empty answer or `not-found` means the unit does not exist.
fn classify_enabled(text: &str) -> anyhow::Result<Enabled> {
    match text.trim() {
        "enabled" | "enabled-runtime" => Ok(Enabled::Enabled),
        // A linked unit file is not enabled: disabling it is the inverse.
        "disabled" | "linked" | "linked-runtime" => Ok(Enabled::Disabled),
        "masked" | "masked-runtime" => Ok(Enabled::Masked),
        "static" | "alias" | "indirect" | "generated" | "transient" => Ok(Enabled::Static),
        "" | "not-found" => Ok(Enabled::NotFound),
        other => anyhow::bail!("unexpected is-enabled output: {other}"),
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
    fn run_transient_executor(
        &self,
        unit: &str,
        exec_args: &[String],
        dirs: &[String],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.enabled,
            "transient units are disabled under IBEXWALL_ROOT"
        );
        // systemd-run is the CLI front-end of StartTransientUnit: fixed
        // argv, no shell. --wait propagates the helper's exit status. The
        // caller names the unit (`apply`/`rollback`): a rollback follows its
        // apply immediately and garbage collection of the finished unit is
        // asynchronous, so the two must not share a name.
        let unit_name = unit;
        let mut command = Command::new("systemd-run");
        command
            .arg("--unit")
            .arg(unit)
            .arg("--collect")
            .arg("--wait")
            .arg("--property")
            .arg("Type=oneshot")
            .arg("--property")
            .arg("NoNewPrivileges=yes")
            .arg("--property")
            .arg("ProtectSystem=strict")
            .arg("--property")
            .arg("ProtectHome=yes")
            .arg("--property")
            .arg("PrivateTmp=yes")
            .arg("--property")
            .arg("SystemCallFilter=@system-service")
            .arg("--property")
            .arg("RestrictAddressFamilies=AF_UNIX AF_NETLINK");
        for dir in dirs {
            command
                .arg("--property")
                .arg(format!("ReadWritePaths={dir}"));
        }
        // Read the result of the run so the core can report details.
        command.arg("--").arg("/usr/bin/ibexwall-exec");
        for arg in exec_args {
            command.arg(arg);
        }
        let output = command.output()?;
        if !output.status.success() {
            anyhow::bail!(
                "executor unit {unit_name} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn snapshot(&self, unit: &str) -> anyhow::Result<UnitSnapshot> {
        anyhow::ensure!(
            self.enabled,
            "systemd control is disabled under IBEXWALL_ROOT"
        );
        // `is-enabled` prints the state but exits non-zero for every state
        // that is not "enabled" (a disabled unit exits 1), so the exit
        // status says nothing; only the text does.
        let output = Command::new("systemctl")
            .args(["is-enabled", unit])
            .output()?;
        let enabled = classify_enabled(&String::from_utf8_lossy(&output.stdout))?;
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
        // Unit files and drop-ins written by a transaction (or put back by
        // its rollback) are only seen after a reload; without one a
        // restart would run the old definition.
        if !matches!(action, UnitAction::Stop) {
            systemctl(&["daemon-reload"])?;
        }
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
    fn run_transient_executor(
        &self,
        unit: &str,
        _exec_args: &[String],
        _dirs: &[String],
    ) -> anyhow::Result<()> {
        self.log.push(format!("transient-exec {unit}"));
        Ok(())
    }

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
    fn is_enabled_text_maps_to_states_including_the_non_zero_exit_ones() {
        for (text, expected) in [
            ("enabled\n", Enabled::Enabled),
            ("enabled-runtime\n", Enabled::Enabled),
            ("disabled\n", Enabled::Disabled),
            ("linked\n", Enabled::Disabled),
            ("masked\n", Enabled::Masked),
            ("static\n", Enabled::Static),
            ("indirect\n", Enabled::Static),
            ("not-found\n", Enabled::NotFound),
            ("", Enabled::NotFound),
        ] {
            assert_eq!(classify_enabled(text).unwrap(), expected, "{text:?}");
        }
        assert!(classify_enabled("surprise").is_err());
    }

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
