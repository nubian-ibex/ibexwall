// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.mounts`: `/tmp` and `/dev/shm` should not honor setuid files or
//! device nodes, and `/dev/shm` should not run programs. The check reads
//! the live mount options (`/proc/mounts`); the control writes owned
//! systemd drop-ins for `tmp.mount` and `dev-shm.mount` (never fstab, never
//! a distro file) that apply at the next boot. Nothing is remounted live:
//! remounting `/tmp` under running programs is the kind of change that
//! cannot be undone cleanly, so the plan says "after reboot" and the
//! rollback is simply removing the drop-ins.

use std::collections::{BTreeMap, BTreeSet};

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Mounts)) {
        eprintln!("ibexwall-plugin-mounts: {err}");
        std::process::exit(1);
    }
}

struct Mounts;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Also forbid running programs from `/tmp` (off by default: it breaks
    /// installers and builds).
    pub tmp_noexec: bool,
}

impl Plugin for Mounts {
    fn id(&self) -> &'static str {
        "system.mounts"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

struct Target {
    mount: &'static str,
    base: &'static str,
    drop_in: &'static str,
}

const TMP: Target = Target {
    mount: "/tmp",
    base: "mode=1777,strictatime",
    drop_in: "/etc/systemd/system/tmp.mount.d/70-ibexwall.conf",
};
const SHM: Target = Target {
    mount: "/dev/shm",
    base: "mode=1777,strictatime",
    drop_in: "/etc/systemd/system/dev-shm.mount.d/70-ibexwall.conf",
};

fn required(target: &Target, tmp_noexec: bool) -> Vec<&'static str> {
    let mut want = vec!["nosuid", "nodev"];
    if target.mount == "/dev/shm" || tmp_noexec {
        want.push("noexec");
    }
    want
}

/// `(fstype, options)` of a mount point; the last entry wins (a later mount
/// hides an earlier one).
fn mount_options(sandbox: &Sandbox, mount: &str) -> Option<(String, BTreeSet<String>)> {
    let text = sandbox.read("/proc/mounts")?;
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (_source, point, fstype, options) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (point == mount).then(|| {
                (
                    fstype.to_string(),
                    options.split(',').map(str::to_string).collect(),
                )
            })
        })
        .next_back()
}

/// systemd owns `/tmp` as a tmpfs only when `tmp.mount` exists and is what
/// mounted it.
fn tmp_is_ours_to_configure(sandbox: &Sandbox) -> bool {
    mount_options(sandbox, "/tmp").is_some_and(|(fstype, _)| fstype == "tmpfs")
        && (sandbox.exists("/usr/lib/systemd/system/tmp.mount")
            || sandbox.exists("/etc/systemd/system/tmp.mount"))
}

fn configured(sandbox: &Sandbox, target: &Target, want: &[&str]) -> bool {
    sandbox
        .read(target.drop_in)
        .is_some_and(|text| want.iter().all(|option| text.contains(option)))
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut results = Vec::new();
    let mut findings = Vec::new();
    for (id, target) in [("mounts.tmp", &TMP), ("mounts.shm", &SHM)] {
        let want = required(target, false);
        let outcome = match mount_options(sandbox, target.mount) {
            // Cannot read the mount table at all: never a pass.
            None if sandbox.read("/proc/mounts").is_none() => CheckOutcome::NotAssessed,
            // /tmp on the root file system has no entry of its own, and no
            // mount unit to configure.
            None if target.mount == "/tmp" => CheckOutcome::NotApplicable,
            None => CheckOutcome::NotAssessed,
            Some((fstype, _)) if target.mount == "/tmp" && fstype != "tmpfs" => {
                CheckOutcome::NotApplicable
            }
            Some((_, options)) => {
                let missing: Vec<&str> = want
                    .iter()
                    .copied()
                    .filter(|o| !options.contains(*o))
                    .collect();
                if missing.is_empty() || configured(sandbox, target, &want) {
                    // Configured for the next boot counts: the plan says so.
                    CheckOutcome::Pass
                } else {
                    let mut args = BTreeMap::new();
                    args.insert("mount".to_string(), target.mount.to_string());
                    args.insert("missing".to_string(), missing.join(", "));
                    args.insert(
                        "options".to_string(),
                        options.iter().cloned().collect::<Vec<_>>().join(","),
                    );
                    findings.push(Finding {
                        id: format!("{id}.open"),
                        plugin: "system.mounts".into(),
                        severity: Severity::Low,
                        title_key: "mounts-open-title".into(),
                        summary_key: "mounts-open-summary".into(),
                        args,
                        references: vec![],
                        remediation: Some(Remediation {
                            plan_template: Some("mounts.harden".into()),
                            may_affect_keys: vec![
                                "mounts-may-affect-programs".into(),
                                "mounts-take-effect-after-reboot".into(),
                            ],
                        }),
                        status: FindingStatus::Open,
                        detected_at: detected_at.into(),
                    });
                    CheckOutcome::Fail
                }
            }
        };
        results.push(CheckResult {
            id: id.into(),
            severity: Severity::Low,
            outcome,
        });
    }
    CheckReport { results, findings }
}

fn drop_in(target: &Target, want: &[&str]) -> Op {
    Op::FileWrite {
        path: target.drop_in.into(),
        content: format!(
            "# Managed by IbexWall (system.mounts). Takes effect at the next boot.\n[Mount]\nOptions={},{}\n",
            target.base,
            want.join(",")
        ),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let mut ops = Vec::new();
    if tmp_is_ours_to_configure(sandbox) {
        ops.push(drop_in(&TMP, &required(&TMP, config.tmp_noexec)));
    }
    if mount_options(sandbox, "/dev/shm").is_some() {
        ops.push(drop_in(&SHM, &required(&SHM, false)));
    }
    if ops.is_empty() {
        return Err(PluginError::invalid(
            "config",
            "nothing to configure: /tmp is not a systemd tmpfs and /dev/shm is not mounted"
                .to_string(),
        ));
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-mnt-{}-{}",
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

    const LOOSE: &str =
        "tmpfs /tmp tmpfs rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n";

    fn outcomes(report: &CheckReport) -> Vec<(String, CheckOutcome)> {
        report
            .results
            .iter()
            .map(|r| (r.id.clone(), r.outcome))
            .collect()
    }

    #[test]
    fn missing_options_are_findings_that_name_what_is_missing() {
        let (root, sandbox) = tree(&[("/proc/mounts", LOOSE)]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(
            outcomes(&report),
            vec![
                ("mounts.tmp".into(), CheckOutcome::Fail),
                ("mounts.shm".into(), CheckOutcome::Fail)
            ]
        );
        let tmp = &report.findings[0];
        assert_eq!(tmp.args["missing"], "nosuid, nodev");
        let shm = &report.findings[1];
        assert_eq!(shm.args["missing"], "noexec");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hardened_mounts_and_configured_for_next_boot_both_pass() {
        let (root, sandbox) = tree(&[(
            "/proc/mounts",
            "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n",
        )]);
        assert!(evaluate(&sandbox, "now").findings.is_empty());
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            ("/proc/mounts", LOOSE),
            (
                "/etc/systemd/system/tmp.mount.d/70-ibexwall.conf",
                "Options=mode=1777,nosuid,nodev\n",
            ),
            (
                "/etc/systemd/system/dev-shm.mount.d/70-ibexwall.conf",
                "Options=mode=1777,nosuid,nodev,noexec\n",
            ),
        ]);
        assert!(evaluate(&sandbox, "now").findings.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tmp_on_the_root_filesystem_is_not_ours_to_configure() {
        let (root, sandbox) = tree(&[(
            "/proc/mounts",
            "/dev/vda1 / ext4 rw 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n",
        )]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::NotApplicable);
        assert_eq!(report.results[1].outcome, CheckOutcome::Pass);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert_eq!(ops.len(), 1, "only /dev/shm");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_writes_owned_drop_ins_and_noexec_for_tmp_is_opt_in() {
        let (root, sandbox) = tree(&[
            ("/proc/mounts", LOOSE),
            ("/usr/lib/systemd/system/tmp.mount", "[Mount]\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        let texts: Vec<(&String, &String)> = ops
            .iter()
            .map(|op| match op {
                Op::FileWrite { path, content, .. } => (path, content),
                _ => panic!(),
            })
            .collect();
        assert_eq!(texts.len(), 2);
        assert!(texts[0].0.ends_with("tmp.mount.d/70-ibexwall.conf"));
        assert!(texts[0].1.contains("nosuid,nodev\n"));
        assert!(!texts[0].1.contains("noexec"));
        assert!(texts[1].1.contains("noexec"));
        let ops = plan(&sandbox, &Config { tmp_noexec: true }).unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        assert!(content.contains("noexec"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nothing_to_configure_is_refused_and_unreadable_mounts_are_not_a_pass() {
        let (root, sandbox) = tree(&[]);
        assert!(plan(&sandbox, &Config::default()).is_err());
        let report = evaluate(&sandbox, "now");
        assert!(
            report
                .results
                .iter()
                .all(|r| r.outcome == CheckOutcome::NotAssessed)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
