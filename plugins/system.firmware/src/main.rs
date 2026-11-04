// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.firmware`: can this computer learn about firmware updates?
//! File-based: virtual machines have no firmware to update (not
//! applicable); on hardware, fwupd must be installed and its refresh timer
//! on. Installing fwupd is the user's job (IbexWall never installs
//! software); the control only turns the refresh timer on. Pending firmware
//! updates and the HSI report come from fwupd itself and are not read here.

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

const TIMER: &str = "fwupd-refresh.timer";

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Firmware)) {
        eprintln!("ibexwall-plugin-firmware: {err}");
        std::process::exit(1);
    }
}

struct Firmware;

impl Plugin for Firmware {
    fn id(&self) -> &'static str {
        "system.firmware"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, _config: Value) -> Result<Vec<Op>, PluginError> {
        plan(&Sandbox::system())
    }
}

fn is_virtual(sandbox: &Sandbox) -> bool {
    ["sys_vendor", "product_name", "bios_vendor"]
        .iter()
        .filter_map(|file| sandbox.read(&format!("/sys/class/dmi/id/{file}")))
        .any(|text| {
            let text = text.to_ascii_lowercase();
            [
                "qemu",
                "kvm",
                "virtualbox",
                "innotek",
                "vmware",
                "xen",
                "bochs",
                "parallels",
                "microsoft corporation virtual",
                "amazon ec2",
                "google compute",
            ]
            .iter()
            .any(|needle| text.contains(needle))
        })
}

fn fwupd_installed(sandbox: &Sandbox) -> bool {
    sandbox.exists("/usr/libexec/fwupd/fwupd") || sandbox.exists("/usr/lib/fwupd/fwupd")
}

fn timer_enabled(sandbox: &Sandbox) -> bool {
    sandbox.exists(&format!("/etc/systemd/system/timers.target.wants/{TIMER}"))
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let finding = |kind: &str, severity, remediation: Option<Remediation>| Finding {
        id: format!("firmware.{kind}"),
        plugin: "system.firmware".into(),
        severity,
        title_key: format!("firmware-{kind}-title"),
        summary_key: format!("firmware-{kind}-summary"),
        args: Default::default(),
        references: vec![],
        remediation,
        status: FindingStatus::Open,
        detected_at: detected_at.into(),
    };
    let outcome = if sandbox.read("/sys/class/dmi/id/sys_vendor").is_none()
        && sandbox.read("/sys/class/dmi/id/product_name").is_none()
    {
        // No DMI data: cannot tell hardware from a container or a board
        // without it. Never a pass.
        CheckOutcome::NotAssessed
    } else if is_virtual(sandbox) {
        CheckOutcome::NotApplicable
    } else if !fwupd_installed(sandbox) {
        findings.push(finding("missing", Severity::Low, None));
        CheckOutcome::Fail
    } else if !timer_enabled(sandbox) {
        findings.push(finding(
            "timer",
            Severity::Low,
            Some(Remediation {
                plan_template: Some("firmware.refresh".into()),
                may_affect_keys: vec![],
            }),
        ));
        CheckOutcome::Fail
    } else {
        CheckOutcome::Pass
    };
    CheckReport {
        results: vec![CheckResult {
            id: "firmware.fwupd".into(),
            severity: Severity::Low,
            outcome,
        }],
        findings,
    }
}

pub fn plan(sandbox: &Sandbox) -> Result<Vec<Op>, PluginError> {
    if !fwupd_installed(sandbox) {
        return Err(PluginError::invalid(
            "config",
            "fwupd is not installed; IbexWall does not install software by itself".to_string(),
        ));
    }
    if !sandbox.exists(&format!("/usr/lib/systemd/system/{TIMER}")) {
        return Err(PluginError::invalid(
            "config",
            "this fwupd has no refresh timer".to_string(),
        ));
    }
    Ok(vec![Op::SystemdUnit {
        unit: TIMER.into(),
        action: UnitAction::Enable,
        now: Some(true),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-fw-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        (root.clone(), Sandbox::at(root))
    }

    const LAPTOP: (&str, &str) = ("/sys/class/dmi/id/sys_vendor", "LENOVO\n");

    fn outcome(sandbox: &Sandbox) -> CheckOutcome {
        evaluate(sandbox, "now").results[0].outcome
    }

    #[test]
    fn a_virtual_machine_has_no_firmware_to_update() {
        for vendor in ["QEMU\n", "Oracle innotek GmbH\n", "VMware, Inc.\n"] {
            let (root, sandbox) = tree(&[("/sys/class/dmi/id/sys_vendor", vendor)]);
            assert_eq!(outcome(&sandbox), CheckOutcome::NotApplicable, "{vendor}");
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn without_dmi_data_it_is_not_assessed() {
        let (root, sandbox) = tree(&[]);
        assert_eq!(outcome(&sandbox), CheckOutcome::NotAssessed);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hardware_needs_fwupd_and_its_timer() {
        let (root, sandbox) = tree(&[LAPTOP]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].id, "firmware.missing");
        assert!(
            report.findings[0].remediation.is_none(),
            "never installs software"
        );
        assert!(plan(&sandbox).is_err());
        std::fs::remove_dir_all(root).unwrap();

        let (root, sandbox) = tree(&[
            LAPTOP,
            ("/usr/libexec/fwupd/fwupd", ""),
            ("/usr/lib/systemd/system/fwupd-refresh.timer", ""),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings[0].id, "firmware.timer");
        let ops = plan(&sandbox).unwrap();
        assert!(
            matches!(&ops[0], Op::SystemdUnit { unit, action: UnitAction::Enable, .. } if unit == TIMER)
        );
        std::fs::remove_dir_all(root).unwrap();

        let (root, sandbox) = tree(&[
            LAPTOP,
            ("/usr/lib/fwupd/fwupd", ""),
            (
                "/etc/systemd/system/timers.target.wants/fwupd-refresh.timer",
                "",
            ),
        ]);
        assert_eq!(outcome(&sandbox), CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
    }
}
