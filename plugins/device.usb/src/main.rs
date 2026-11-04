// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `device.usb`: new USB devices should wait for permission (USBGuard).
//! The check looks at whether USBGuard is installed, enabled and has rules.
//! The control builds an allow list from the devices plugged in right now
//! (read from sysfs, so the keyboard and mouse in use stay allowed and
//! nobody is locked out), writes it as one owned rules file and enables the
//! service. It never installs USBGuard. Everything not on the list is
//! blocked by USBGuard's default policy.

use std::collections::BTreeSet;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

const RULES: &str = "/etc/usbguard/rules.d/70-ibexwall.conf";

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Usb)) {
        eprintln!("ibexwall-plugin-usb: {err}");
        std::process::exit(1);
    }
}

struct Usb;

impl Plugin for Usb {
    fn id(&self) -> &'static str {
        "device.usb"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, _config: Value) -> Result<Vec<Op>, PluginError> {
        plan(&Sandbox::system())
    }
}

fn installed(sandbox: &Sandbox) -> bool {
    sandbox.exists("/usr/sbin/usbguard-daemon") || sandbox.exists("/usr/bin/usbguard-daemon")
}

/// Enabled means a `*.wants` directory under /etc/systemd/system links the
/// service: which target depends on the distribution's unit (Fedora's is
/// WantedBy=basic.target, Debian's multi-user.target).
fn enabled(sandbox: &Sandbox) -> bool {
    sandbox
        .list("/etc/systemd/system")
        .iter()
        .filter(|dir| dir.ends_with(".wants"))
        .any(|dir| sandbox.exists(&format!("/etc/systemd/system/{dir}/usbguard.service")))
}

/// A rule line that is not a comment, in the main file or the rules folder.
fn has_rules(sandbox: &Sandbox) -> bool {
    let mut files = vec!["/etc/usbguard/rules.conf".to_string()];
    for name in sandbox.list("/etc/usbguard/rules.d") {
        files.push(format!("/etc/usbguard/rules.d/{name}"));
    }
    files.iter().any(|file| {
        sandbox.read(file).is_some_and(|text| {
            text.lines().map(str::trim).any(|l| {
                l.starts_with("allow") || l.starts_with("block") || l.starts_with("reject")
            })
        })
    })
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let finding = |kind: &str, remediation| Finding {
        id: format!("usb.{kind}"),
        plugin: "device.usb".into(),
        severity: Severity::Medium,
        title_key: format!("usb-{kind}-title"),
        summary_key: format!("usb-{kind}-summary"),
        args: Default::default(),
        references: vec![],
        remediation,
        status: FindingStatus::Open,
        detected_at: detected_at.into(),
    };
    let mut findings = Vec::new();
    let outcome = if !sandbox.exists("/sys/bus/usb/devices") {
        // No USB bus (a virtual machine without a controller): nothing can
        // be plugged in, and USBGuard cannot even start there.
        CheckOutcome::NotApplicable
    } else if !installed(sandbox) {
        findings.push(finding("missing", None));
        CheckOutcome::Fail
    } else if enabled(sandbox) && has_rules(sandbox) {
        CheckOutcome::Pass
    } else {
        findings.push(finding(
            "off",
            Some(Remediation {
                plan_template: Some("usb.guard".into()),
                may_affect_keys: vec!["usb-may-affect-new-devices".into()],
            }),
        ));
        CheckOutcome::Fail
    };
    CheckReport {
        results: vec![CheckResult {
            id: "usb.guard".into(),
            severity: Severity::Medium,
            outcome,
        }],
        findings,
    }
}

/// `vvvv:pppp` of every USB device (not interface) in sysfs.
fn plugged_in(sandbox: &Sandbox) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for name in sandbox.list("/sys/bus/usb/devices") {
        // Interfaces look like `1-1:1.0`; devices like `1-1` or `usb1`.
        if name.contains(':') {
            continue;
        }
        let read = |file: &str| {
            sandbox
                .read(&format!("/sys/bus/usb/devices/{name}/{file}"))
                .map(|t| t.trim().to_ascii_lowercase())
        };
        if let (Some(vendor), Some(product)) = (read("idVendor"), read("idProduct"))
            && is_hex4(&vendor)
            && is_hex4(&product)
        {
            ids.insert(format!("{vendor}:{product}"));
        }
    }
    ids
}

fn is_hex4(text: &str) -> bool {
    text.len() == 4 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn plan(sandbox: &Sandbox) -> Result<Vec<Op>, PluginError> {
    if !sandbox.exists("/sys/bus/usb/devices") {
        return Err(PluginError::invalid(
            "config",
            "this machine has no USB bus; there is nothing to guard".to_string(),
        ));
    }
    if !installed(sandbox) {
        return Err(PluginError::invalid(
            "config",
            "USBGuard is not installed; IbexWall does not install software by itself".to_string(),
        ));
    }
    if !sandbox.exists("/usr/lib/systemd/system/usbguard.service")
        && !sandbox.exists("/etc/systemd/system/usbguard.service")
    {
        return Err(PluginError::invalid(
            "config",
            "this USBGuard has no systemd service".to_string(),
        ));
    }
    let mut content = String::from(
        "# Managed by IbexWall (device.usb): what was plugged in when this was made.\n# Everything else waits for `usbguard allow-device`.\n",
    );
    // Hubs carry other devices; without them nothing behind a hub appears.
    content.push_str("allow with-interface equals { 09:*:* }\n");
    for id in plugged_in(sandbox) {
        content.push_str(&format!("allow id {id}\n"));
    }
    Ok(vec![
        Op::FileWrite {
            path: RULES.into(),
            content,
            // USBGuard refuses rule files that anyone but root can read.
            mode: "0600".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        Op::SystemdUnit {
            unit: "usbguard.service".into(),
            action: UnitAction::Enable,
            now: Some(true),
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-usb-{}-{}",
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

    const DAEMON: (&str, &str) = ("/usr/sbin/usbguard-daemon", "");
    const BUS: (&str, &str) = ("/sys/bus/usb/devices/.keep", "");
    const UNIT: (&str, &str) = ("/usr/lib/systemd/system/usbguard.service", "");

    #[test]
    fn missing_usbguard_is_a_finding_without_a_plan() {
        let (root, sandbox) = tree(&[BUS]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings[0].id, "usb.missing");
        assert!(report.findings[0].remediation.is_none());
        assert!(
            plan(&sandbox)
                .unwrap_err()
                .to_string()
                .contains("does not install software")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enforcing_needs_the_service_enabled_and_real_rules() {
        let (root, sandbox) = tree(&[DAEMON, BUS]);
        assert_eq!(evaluate(&sandbox, "now").findings[0].id, "usb.off");
        std::fs::remove_dir_all(root).unwrap();
        // Enabled but only comments: still not enforcing.
        let (root, sandbox) = tree(&[
            DAEMON,
            BUS,
            (
                "/etc/systemd/system/multi-user.target.wants/usbguard.service",
                "",
            ),
            ("/etc/usbguard/rules.conf", "# nothing\n"),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            DAEMON,
            BUS,
            (
                "/etc/systemd/system/multi-user.target.wants/usbguard.service",
                "",
            ),
            (
                "/etc/usbguard/rules.d/70-ibexwall.conf",
                "allow id 1d6b:0002\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_allows_hubs_and_what_is_plugged_in_and_nothing_else() {
        let (root, sandbox) = tree(&[
            DAEMON,
            UNIT,
            BUS,
            ("/sys/bus/usb/devices/usb1/idVendor", "1d6b\n"),
            ("/sys/bus/usb/devices/usb1/idProduct", "0002\n"),
            ("/sys/bus/usb/devices/1-1/idVendor", "046D\n"),
            ("/sys/bus/usb/devices/1-1/idProduct", "C52B\n"),
            // An interface, a duplicate and junk are not extra rules.
            ("/sys/bus/usb/devices/1-1:1.0/idVendor", "ffff\n"),
            ("/sys/bus/usb/devices/2-1/idVendor", "046d\n"),
            ("/sys/bus/usb/devices/2-1/idProduct", "c52b\n"),
            ("/sys/bus/usb/devices/3-1/idVendor", "zzzz\n"),
            ("/sys/bus/usb/devices/3-1/idProduct", "0001\n"),
        ]);
        let ops = plan(&sandbox).unwrap();
        let Op::FileWrite {
            path,
            content,
            mode,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!(path, RULES);
        assert_eq!(mode, "0600", "USBGuard refuses world-readable rule files");
        let rules: Vec<&str> = content.lines().filter(|l| l.starts_with("allow")).collect();
        assert_eq!(
            rules,
            [
                "allow with-interface equals { 09:*:* }",
                "allow id 046d:c52b",
                "allow id 1d6b:0002"
            ]
        );
        assert!(!content.contains("ffff") && !content.contains("zzzz"));
        assert!(
            matches!(&ops[1], Op::SystemdUnit { unit, action: UnitAction::Enable, now: Some(true) } if unit == "usbguard.service")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_usbguard_without_a_service_is_refused() {
        let (root, sandbox) = tree(&[DAEMON, BUS]);
        assert!(
            plan(&sandbox)
                .unwrap_err()
                .to_string()
                .contains("no systemd service")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
