// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The posture checks. Each returns an outcome; failed checks also yield a
//! finding whose message keys live in `locales/*.ftl`.
//!
//! Rules every check follows:
//! - missing or unreadable input is `NotAssessed` (or `NotApplicable` when
//!   the feature cannot exist on this system), never a pass;
//! - wording keys are stable ids, text is never built here.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::Sandbox;

use crate::blockdev::{Encryption, device_encryption};

/// Fixed GUID of the EFI global variable namespace (UEFI specification).
const SECURE_BOOT_VAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

struct Check {
    id: &'static str,
    severity: Severity,
    outcome: CheckOutcome,
    args: BTreeMap<String, String>,
}

impl Check {
    fn new(id: &'static str, severity: Severity, outcome: CheckOutcome) -> Self {
        Self {
            id,
            severity,
            outcome,
            args: BTreeMap::new(),
        }
    }

    fn arg(mut self, key: &str, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let root_encryption = root_encryption(sandbox);
    let mounts = sandbox.read("/proc/self/mounts");
    let checks = vec![
        secure_boot(sandbox),
        lockdown(sandbox),
        disk_encryption(root_encryption),
        swap_encryption(sandbox, root_encryption),
        tpm2(sandbox),
        mandatory_access_control(sandbox),
        firewall(sandbox),
        mount_options(mounts.as_deref(), "/tmp", "posture.tmp_mount"),
        mount_options(mounts.as_deref(), "/dev/shm", "posture.shm_mount"),
        core_dumps(sandbox),
        sudo_nopasswd(sandbox),
        // Need PackageKit / fwupd: shown honestly until F7.
        Check::new(
            "posture.updates_pending",
            Severity::High,
            CheckOutcome::NotAssessed,
        ),
        Check::new(
            "posture.updates_automatic",
            Severity::Medium,
            CheckOutcome::NotAssessed,
        ),
        Check::new(
            "posture.firmware_hsi",
            Severity::Low,
            CheckOutcome::NotAssessed,
        ),
    ];

    let mut report = CheckReport::default();
    for check in checks {
        report.results.push(CheckResult {
            id: check.id.into(),
            severity: check.severity,
            outcome: check.outcome,
        });
        if check.outcome == CheckOutcome::Fail {
            let key = check.id.replace(['.', '_'], "-");
            report.findings.push(Finding {
                id: check.id.into(),
                plugin: "system.posture".into(),
                severity: check.severity,
                title_key: format!("{key}-title"),
                summary_key: format!("{key}-summary"),
                args: check.args,
                references: vec![],
                remediation: None,
                status: FindingStatus::Open,
                detected_at: detected_at.into(),
            });
        }
    }
    report
        .findings
        .push(mandatory_access_note(sandbox, detected_at));
    report
}

/// Which mandatory access control the machine has and how it is set.
fn mandatory_access_note(sandbox: &Sandbox, at: &str) -> Finding {
    use ibexwall_sdk::detect::{detected, install_command};
    let selinux = sandbox.read("/sys/fs/selinux/enforce");
    let apparmor = sandbox.read("/sys/module/apparmor/parameters/enabled");
    let mut args = BTreeMap::new();
    let case = if selinux.as_deref().map(str::trim) == Some("1") {
        "selinux-enforcing"
    } else if apparmor.as_deref().map(str::trim) == Some("Y") {
        "apparmor"
    } else if selinux.as_deref().map(str::trim) == Some("0") {
        "selinux-permissive"
    } else if sandbox
        .read("/etc/selinux/config")
        .is_some_and(|c| c.lines().any(|l| l.trim() == "SELINUX=disabled"))
    {
        "selinux-disabled"
    } else {
        // Fedora ships SELinux, the others AppArmor; IbexWall installs
        // nothing and a boot setting is the person's to change.
        let release = sandbox.read("/etc/os-release").unwrap_or_default();
        let package = if release.contains("fedora") || release.contains("rhel") {
            "selinux-policy-targeted"
        } else {
            "apparmor"
        };
        args.insert(
            "install".into(),
            install_command(sandbox, package)
                .unwrap_or_else(|| format!("your package manager: {package}")),
        );
        "none"
    };
    detected("system.posture", "mac", case, args, None, at)
}

fn secure_boot(sandbox: &Sandbox) -> Check {
    let id = "posture.secure_boot";
    if !sandbox.exists("/sys/firmware/efi") {
        // Legacy BIOS boot: Secure Boot cannot exist here.
        return Check::new(id, Severity::Medium, CheckOutcome::NotApplicable);
    }
    // 4 attribute bytes, then one data byte (1 = enabled).
    match sandbox.read_bytes(SECURE_BOOT_VAR).as_deref() {
        Some([_, _, _, _, 1, ..]) => Check::new(id, Severity::Medium, CheckOutcome::Pass),
        Some([_, _, _, _, 0, ..]) => Check::new(id, Severity::Medium, CheckOutcome::Fail),
        _ => Check::new(id, Severity::Medium, CheckOutcome::NotAssessed),
    }
}

/// `none [integrity] confidentiality`: the bracketed word is active.
fn lockdown(sandbox: &Sandbox) -> Check {
    let id = "posture.lockdown";
    let Some(text) = sandbox.read("/sys/kernel/security/lockdown") else {
        return Check::new(id, Severity::Low, CheckOutcome::NotAssessed);
    };
    match active_word(&text) {
        Some("none") => Check::new(id, Severity::Low, CheckOutcome::Fail),
        Some(_) => Check::new(id, Severity::Low, CheckOutcome::Pass),
        None => Check::new(id, Severity::Low, CheckOutcome::NotAssessed),
    }
}

fn active_word(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = text[start..].find(']')? + start;
    Some(text[start..end].trim())
}

/// Source device of the root filesystem, from `/proc/self/mounts`.
fn root_source(mounts: &str) -> Option<&str> {
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let source = fields.next()?;
            (fields.next()? == "/").then_some(source)
        })
        // The last mount on "/" wins (initramfs mounts precede the real one).
        .next_back()
}

fn root_encryption(sandbox: &Sandbox) -> Encryption {
    match sandbox.read("/proc/self/mounts") {
        Some(mounts) => match root_source(&mounts) {
            Some(source) => device_encryption(sandbox, source),
            None => Encryption::Unknown,
        },
        None => Encryption::Unknown,
    }
}

fn disk_encryption(root: Encryption) -> Check {
    let id = "posture.disk_encryption";
    let outcome = match root {
        Encryption::Encrypted => CheckOutcome::Pass,
        Encryption::Plain => CheckOutcome::Fail,
        Encryption::Unknown => CheckOutcome::NotAssessed,
    };
    Check::new(id, Severity::High, outcome)
}

fn swap_encryption(sandbox: &Sandbox, root: Encryption) -> Check {
    let id = "posture.swap_encryption";
    let Some(swaps) = sandbox.read("/proc/swaps") else {
        return Check::new(id, Severity::Medium, CheckOutcome::NotAssessed);
    };
    let mut verdicts = Vec::new();
    for line in swaps.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(path), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        verdicts.push(if path.starts_with("/dev/zram") {
            Encryption::Encrypted // lives in RAM only
        } else if kind == "file" {
            root // a swap file lives on the root filesystem
        } else {
            device_encryption(sandbox, path)
        });
    }
    let outcome = if verdicts.is_empty() {
        CheckOutcome::NotApplicable // no swap, nothing to protect
    } else if verdicts.contains(&Encryption::Plain) {
        CheckOutcome::Fail
    } else if verdicts.contains(&Encryption::Unknown) {
        CheckOutcome::NotAssessed
    } else {
        CheckOutcome::Pass
    };
    Check::new(id, Severity::Medium, outcome)
}

fn tpm2(sandbox: &Sandbox) -> Check {
    let outcome = if sandbox.exists("/sys/class/tpm/tpm0") {
        CheckOutcome::Pass
    } else {
        CheckOutcome::NotApplicable
    };
    // Informational (weight 0): it cannot lower the score.
    Check::new("posture.tpm2", Severity::Info, outcome)
}

fn mandatory_access_control(sandbox: &Sandbox) -> Check {
    let id = "posture.mac";
    let selinux = sandbox.read("/sys/fs/selinux/enforce");
    let apparmor = sandbox.read("/sys/module/apparmor/parameters/enabled");
    if selinux.as_deref().map(str::trim) == Some("1")
        || apparmor.as_deref().map(str::trim) == Some("Y")
    {
        return Check::new(id, Severity::Medium, CheckOutcome::Pass);
    }
    let mode = match selinux.as_deref().map(str::trim) {
        Some("0") => "selinux-permissive",
        _ => "none",
    };
    Check::new(id, Severity::Medium, CheckOutcome::Fail).arg("mode", mode)
}

/// An active firewall. systemd leaves `invocation:<unit>` under
/// `/run/systemd/units` for every started unit. `ufw.service` also runs
/// when ufw is disabled, so it only counts when `ufw.conf` says
/// `ENABLED=yes`. This says a firewall is running, not that its rules are
/// good.
fn firewall(sandbox: &Sandbox) -> Check {
    let id = "posture.firewall";
    if !sandbox.exists("/run/systemd/units") {
        return Check::new(id, Severity::High, CheckOutcome::NotAssessed);
    }
    let running = |unit: &str| sandbox.exists(&format!("/run/systemd/units/invocation:{unit}"));
    let ufw_enabled = sandbox.read("/etc/ufw/ufw.conf").is_some_and(|conf| {
        conf.lines()
            .map(str::trim)
            .any(|line| line.eq_ignore_ascii_case("ENABLED=yes"))
    });
    let active = running("firewalld.service")
        || running("nftables.service")
        || (running("ufw.service") && ufw_enabled);
    let outcome = if active {
        CheckOutcome::Pass
    } else {
        CheckOutcome::Fail
    };
    Check::new(id, Severity::High, outcome)
}

fn mount_options(mounts: Option<&str>, mount_point: &str, id: &'static str) -> Check {
    let Some(mounts) = mounts else {
        return Check::new(id, Severity::Low, CheckOutcome::NotAssessed);
    };
    // The last entry for a mount point is the visible one.
    let options = mounts
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 4 && fields[1] == mount_point).then(|| fields[3])
        })
        .next_back();
    match options {
        Some(options) => {
            let set: Vec<&str> = options.split(',').collect();
            if set.contains(&"nodev") && set.contains(&"nosuid") {
                Check::new(id, Severity::Low, CheckOutcome::Pass)
            } else {
                Check::new(id, Severity::Low, CheckOutcome::Fail).arg("separate", "yes")
            }
        }
        None => Check::new(id, Severity::Low, CheckOutcome::Fail).arg("separate", "no"),
    }
}

/// `fs.suid_dumpable`: 0 = no dumps, 2 = dumps readable by root only (both
/// fine); 1 = dumps of privileged programs readable by their owner (not).
fn core_dumps(sandbox: &Sandbox) -> Check {
    let id = "posture.core_dumps";
    match sandbox
        .read("/proc/sys/fs/suid_dumpable")
        .as_deref()
        .map(str::trim)
    {
        Some("0" | "2") => Check::new(id, Severity::Low, CheckOutcome::Pass),
        Some(_) => Check::new(id, Severity::Low, CheckOutcome::Fail),
        None => Check::new(id, Severity::Low, CheckOutcome::NotAssessed),
    }
}

/// Passwordless sudo. `/etc/sudoers` is root-only; without the capability
/// the check is "not assessed".
fn sudo_nopasswd(sandbox: &Sandbox) -> Check {
    let id = "posture.sudo_nopasswd";
    if !sandbox.exists("/etc/sudoers") {
        return Check::new(id, Severity::Medium, CheckOutcome::NotApplicable);
    }
    let Some(main) = sandbox.read("/etc/sudoers") else {
        return Check::new(id, Severity::Medium, CheckOutcome::NotAssessed);
    };
    let mut texts = vec![main];
    if sandbox.is_unreadable_dir("/etc/sudoers.d") {
        return Check::new(id, Severity::Medium, CheckOutcome::NotAssessed);
    }
    for name in sandbox.list("/etc/sudoers.d") {
        // sudo ignores files with a dot or ending in '~'.
        if name.contains('.') || name.ends_with('~') {
            continue;
        }
        match sandbox.read(&format!("/etc/sudoers.d/{name}")) {
            Some(text) => texts.push(text),
            None => return Check::new(id, Severity::Medium, CheckOutcome::NotAssessed),
        }
    }
    let found = texts.iter().any(|text| has_nopasswd(text));
    let outcome = if found {
        CheckOutcome::Fail
    } else {
        CheckOutcome::Pass
    };
    Check::new(id, Severity::Medium, outcome)
}

fn has_nopasswd(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .any(|line| line.contains("NOPASSWD"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &[u8])], name: &str) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-post-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    fn outcome(report: &CheckReport, id: &str) -> CheckOutcome {
        report.results.iter().find(|r| r.id == id).unwrap().outcome
    }

    #[test]
    fn an_empty_tree_never_claims_a_pass() {
        let (root, sandbox) = tree(&[], "empty");
        let report = evaluate(&sandbox, "t");
        for result in &report.results {
            assert_ne!(
                result.outcome,
                CheckOutcome::Pass,
                "{} passed on nothing",
                result.id
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn secure_boot_reads_the_efi_variable() {
        for (byte, expected) in [(1u8, CheckOutcome::Pass), (0u8, CheckOutcome::Fail)] {
            let (root, sandbox) = tree(&[(SECURE_BOOT_VAR, &[6, 0, 0, 0, byte][..])], "sb");
            assert_eq!(secure_boot(&sandbox).outcome, expected);
            let _ = std::fs::remove_dir_all(root);
        }
        let (root, sandbox) = tree(&[("/sys/firmware/efi/.keep", b"")], "sb2");
        assert_eq!(secure_boot(&sandbox).outcome, CheckOutcome::NotAssessed);
        let (root2, bios) = tree(&[("/etc/hostname", b"x")], "sb3");
        assert_eq!(secure_boot(&bios).outcome, CheckOutcome::NotApplicable);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(root2);
    }

    #[test]
    fn lockdown_uses_the_bracketed_mode() {
        assert_eq!(
            active_word("none [integrity] confidentiality\n"),
            Some("integrity")
        );
        assert_eq!(
            active_word("[none] integrity confidentiality"),
            Some("none")
        );
        assert_eq!(active_word("garbage"), None);
        let (root, sandbox) = tree(
            &[("/sys/kernel/security/lockdown", b"[none] integrity\n")],
            "ld",
        );
        assert_eq!(lockdown(&sandbox).outcome, CheckOutcome::Fail);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn root_source_prefers_the_last_mount_on_slash() {
        let mounts =
            "rootfs / rootfs rw 0 0\n/dev/mapper/luks-1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n";
        assert_eq!(root_source(mounts), Some("/dev/mapper/luks-1"));
        assert_eq!(root_source("proc /proc proc rw 0 0\n"), None);
    }

    #[test]
    fn encryption_checks_follow_the_root_device() {
        let (root, sandbox) = tree(
            &[
                ("/proc/self/mounts", b"/dev/mapper/luks-1 / ext4 rw 0 0\n"),
                ("/sys/block/dm-0/dm/name", b"luks-1\n"),
                ("/sys/block/dm-0/dm/uuid", b"CRYPT-LUKS2-x\n"),
                (
                    "/proc/swaps",
                    b"Filename Type Size Used Priority\n/swapfile file 1 0 -2\n",
                ),
            ],
            "enc",
        );
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "posture.disk_encryption"),
            CheckOutcome::Pass
        );
        assert_eq!(
            outcome(&report, "posture.swap_encryption"),
            CheckOutcome::Pass
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn plain_root_and_plain_swap_partition_fail() {
        let (root, sandbox) = tree(
            &[
                ("/proc/self/mounts", b"/dev/vda1 / ext4 rw 0 0\n"),
                (
                    "/proc/swaps",
                    b"Filename Type Size Used Priority\n/dev/vda2 partition 1 0 -2\n",
                ),
            ],
            "plain",
        );
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "posture.disk_encryption"),
            CheckOutcome::Fail
        );
        assert_eq!(
            outcome(&report, "posture.swap_encryption"),
            CheckOutcome::Fail
        );
        let finding = report
            .findings
            .iter()
            .find(|f| f.id == "posture.disk_encryption")
            .unwrap();
        assert_eq!(finding.title_key, "posture-disk-encryption-title");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn zram_swap_is_fine_and_no_swap_is_not_applicable() {
        let (root, sandbox) = tree(
            &[(
                "/proc/swaps",
                b"Filename Type Size Used Priority\n/dev/zram0 partition 1 0 100\n",
            )],
            "zram",
        );
        assert_eq!(
            swap_encryption(&sandbox, Encryption::Plain).outcome,
            CheckOutcome::Pass
        );
        let (root2, none) = tree(
            &[("/proc/swaps", b"Filename Type Size Used Priority\n")],
            "noswap",
        );
        assert_eq!(
            swap_encryption(&none, Encryption::Plain).outcome,
            CheckOutcome::NotApplicable
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(root2);
    }

    #[test]
    fn mac_passes_for_enforcing_selinux_or_apparmor_only() {
        let (r1, selinux) = tree(&[("/sys/fs/selinux/enforce", b"1")], "se1");
        assert_eq!(
            mandatory_access_control(&selinux).outcome,
            CheckOutcome::Pass
        );
        let (r2, apparmor) = tree(&[("/sys/module/apparmor/parameters/enabled", b"Y\n")], "aa");
        assert_eq!(
            mandatory_access_control(&apparmor).outcome,
            CheckOutcome::Pass
        );
        let (r3, permissive) = tree(&[("/sys/fs/selinux/enforce", b"0")], "se0");
        let check = mandatory_access_control(&permissive);
        assert_eq!(check.outcome, CheckOutcome::Fail);
        assert_eq!(check.args["mode"], "selinux-permissive");
        let (r4, nothing) = tree(&[], "mac-none");
        assert_eq!(mandatory_access_control(&nothing).args["mode"], "none");
        for r in [r1, r2, r3, r4] {
            let _ = std::fs::remove_dir_all(r);
        }
    }

    #[test]
    fn the_mac_note_tells_each_case_and_gives_the_install_command_only_when_there_is_none() {
        let case = |files: &[(&str, &[u8])], name: &str| {
            let (root, sandbox) = tree(files, name);
            let note = mandatory_access_note(&sandbox, "x");
            let _ = std::fs::remove_dir_all(root);
            note
        };
        assert_eq!(
            case(&[("/sys/fs/selinux/enforce", b"1")], "n1").summary_key,
            "detect-mac-selinux-enforcing"
        );
        assert_eq!(
            case(&[("/sys/module/apparmor/parameters/enabled", b"Y\n")], "n2").summary_key,
            "detect-mac-apparmor"
        );
        assert_eq!(
            case(&[("/sys/fs/selinux/enforce", b"0")], "n3").summary_key,
            "detect-mac-selinux-permissive"
        );
        assert_eq!(
            case(&[("/etc/selinux/config", b"SELINUX=disabled\n")], "n4").summary_key,
            "detect-mac-selinux-disabled"
        );
        let fedora = case(&[("/etc/os-release", b"ID=fedora\n")], "n5");
        assert_eq!(fedora.summary_key, "detect-mac-none");
        assert_eq!(
            fedora.args["install"],
            "sudo dnf install selinux-policy-targeted"
        );
        let ubuntu = case(&[("/etc/os-release", b"ID=ubuntu\nID_LIKE=debian\n")], "n6");
        assert_eq!(ubuntu.args["install"], "sudo apt install apparmor");
        assert!(
            !fedora.args.contains_key("patch"),
            "a boot setting is never changed for the person"
        );
    }

    #[test]
    fn firewall_needs_a_running_firewall_service() {
        let (r1, up) = tree(
            &[("/run/systemd/units/invocation:firewalld.service", b"")],
            "fw1",
        );
        assert_eq!(firewall(&up).outcome, CheckOutcome::Pass);
        let (r2, down) = tree(&[("/run/systemd/units/.keep", b"")], "fw2");
        assert_eq!(firewall(&down).outcome, CheckOutcome::Fail);
        let (r3, unknown) = tree(&[], "fw3");
        assert_eq!(firewall(&unknown).outcome, CheckOutcome::NotAssessed);
        // ufw.service runs even when ufw is disabled.
        let (r4, ufw_off) = tree(
            &[
                ("/run/systemd/units/invocation:ufw.service", b""),
                ("/etc/ufw/ufw.conf", b"# x\nENABLED=no\n"),
            ],
            "fw4",
        );
        assert_eq!(firewall(&ufw_off).outcome, CheckOutcome::Fail);
        let (r5, ufw_on) = tree(
            &[
                ("/run/systemd/units/invocation:ufw.service", b""),
                ("/etc/ufw/ufw.conf", b"ENABLED=yes\n"),
            ],
            "fw5",
        );
        assert_eq!(firewall(&ufw_on).outcome, CheckOutcome::Pass);
        for r in [r1, r2, r3, r4, r5] {
            let _ = std::fs::remove_dir_all(r);
        }
    }

    #[test]
    fn mount_options_distinguish_hardened_unhardened_and_missing() {
        let mounts = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid 0 0\n";
        assert_eq!(
            mount_options(Some(mounts), "/tmp", "posture.tmp_mount").outcome,
            CheckOutcome::Pass
        );
        let shm = mount_options(Some(mounts), "/dev/shm", "posture.shm_mount");
        assert_eq!(
            (shm.outcome, shm.args["separate"].as_str()),
            (CheckOutcome::Fail, "yes")
        );
        let none = mount_options(
            Some("/dev/vda1 / ext4 rw 0 0\n"),
            "/tmp",
            "posture.tmp_mount",
        );
        assert_eq!(
            (none.outcome, none.args["separate"].as_str()),
            (CheckOutcome::Fail, "no")
        );
        assert_eq!(
            mount_options(None, "/tmp", "posture.tmp_mount").outcome,
            CheckOutcome::NotAssessed
        );
    }

    #[test]
    fn core_dump_check_reads_suid_dumpable() {
        for (value, expected) in [
            ("0\n", CheckOutcome::Pass),
            ("2\n", CheckOutcome::Pass),
            ("1\n", CheckOutcome::Fail),
        ] {
            let (root, sandbox) = tree(&[("/proc/sys/fs/suid_dumpable", value.as_bytes())], "cd");
            assert_eq!(core_dumps(&sandbox).outcome, expected);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn sudo_nopasswd_scans_sudoers_and_dropins_but_not_comments() {
        assert!(has_nopasswd("ibex ALL=(ALL) NOPASSWD:ALL\n"));
        assert!(!has_nopasswd(
            "# ibex ALL=(ALL) NOPASSWD:ALL\n   \n%wheel ALL=(ALL) ALL\n"
        ));

        let (r1, clean) = tree(&[("/etc/sudoers", b"%wheel ALL=(ALL) ALL\n")], "su1");
        assert_eq!(sudo_nopasswd(&clean).outcome, CheckOutcome::Pass);
        let (r2, dropin) = tree(
            &[
                ("/etc/sudoers", b"%wheel ALL=(ALL) ALL\n"),
                (
                    "/etc/sudoers.d/90-cloud-init-users",
                    b"ibex ALL=(ALL) NOPASSWD:ALL\n",
                ),
            ],
            "su2",
        );
        assert_eq!(sudo_nopasswd(&dropin).outcome, CheckOutcome::Fail);
        // Files with a dot are ignored by sudo, so they cannot grant access.
        let (r3, ignored) = tree(
            &[
                ("/etc/sudoers", b"%wheel ALL=(ALL) ALL\n"),
                ("/etc/sudoers.d/old.bak", b"ibex ALL=(ALL) NOPASSWD:ALL\n"),
            ],
            "su3",
        );
        assert_eq!(sudo_nopasswd(&ignored).outcome, CheckOutcome::Pass);
        let (r4, nosudo) = tree(&[], "su4");
        assert_eq!(sudo_nopasswd(&nosudo).outcome, CheckOutcome::NotApplicable);
        for r in [r1, r2, r3, r4] {
            let _ = std::fs::remove_dir_all(r);
        }
    }

    #[test]
    fn not_assessed_checks_stay_out_of_the_score() {
        let (root, sandbox) = tree(&[("/proc/sys/fs/suid_dumpable", b"0")], "score");
        let report = evaluate(&sandbox, "t");
        // Only core_dumps (low, pass) and the failed filesystem-less checks
        // matter; updates/firmware are NotAssessed and excluded.
        for id in [
            "posture.updates_pending",
            "posture.updates_automatic",
            "posture.firmware_hsi",
        ] {
            assert_eq!(outcome(&report, id), CheckOutcome::NotAssessed);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Message keys for the plugin exist in every shipped language, with
    /// the same set of keys (a missing translation is a release blocker).
    #[test]
    fn every_check_has_messages_in_english_and_portuguese() {
        let en = include_str!("../locales/en.ftl");
        let pt = include_str!("../locales/pt-BR.ftl");
        let keys = |text: &str| -> std::collections::BTreeSet<String> {
            text.lines()
                .filter(|l| !l.starts_with([' ', '#']) && l.contains(" ="))
                .map(|l| l.split(" =").next().unwrap().to_string())
                .collect()
        };
        assert_eq!(keys(en), keys(pt), "en and pt-BR must define the same keys");
        let (root, sandbox) = tree(&[], "ftl");
        for result in evaluate(&sandbox, "t").results {
            let base = result.id.replace(['.', '_'], "-");
            for suffix in ["name", "title", "summary"] {
                let key = format!("{base}-{suffix}");
                assert!(keys(en).contains(&key), "missing en key {key}");
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Runs the plugin against the real files collected from each distro
    /// (`cargo xtask vm-test --distro <id> --phase fixtures`) and compares
    /// with the reviewed `expected-posture.json` next to them. Regenerate
    /// with `UPDATE_GOLDEN=1` and review the diff before committing.
    #[test]
    fn real_distro_fixtures_match_the_reviewed_expectations() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures");
        let mut checked = 0;
        for entry in std::fs::read_dir(&base).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let report = evaluate(&Sandbox::at(&dir), "t");
            let mut actual = std::collections::BTreeMap::new();
            for result in &report.results {
                actual.insert(result.id.clone(), format!("{:?}", result.outcome));
            }
            let golden = dir.join("expected-posture.json");
            let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
            if std::env::var_os("UPDATE_GOLDEN").is_some() {
                std::fs::write(&golden, &text).unwrap();
            }
            let expected = std::fs::read_to_string(&golden).unwrap_or_else(|_| {
                panic!("missing {}; run with UPDATE_GOLDEN=1", golden.display())
            });
            assert_eq!(text, expected, "fixture {} drifted", dir.display());
            checked += 1;
        }
        assert!(checked >= 1, "no fixtures found under {}", base.display());
    }
}
