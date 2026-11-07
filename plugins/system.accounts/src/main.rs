// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.accounts`: account hygiene, read-only. Empty passwords (a real
//! login shell and nothing in the shadow password field), extra accounts
//! with user id 0, and whether repeated wrong passwords are slowed down
//! (faillock). Needs to read `/etc/shadow`; when it cannot, the check says
//! "not assessed", never a pass. Account names are untrusted text and
//! travel as arguments only.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Accounts)) {
        eprintln!("ibexwall-plugin-accounts: {err}");
        std::process::exit(1);
    }
}

struct Accounts;

impl Plugin for Accounts {
    fn id(&self) -> &'static str {
        "system.accounts"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// Shells that do not allow a login.
fn can_login(shell: &str) -> bool {
    let name = shell.rsplit('/').next().unwrap_or("");
    !(shell.is_empty() || matches!(name, "nologin" | "false" | "sync" | "shutdown" | "halt"))
}

struct Passwd {
    name: String,
    uid: u32,
    shell: String,
}

fn passwd(sandbox: &Sandbox) -> Option<Vec<Passwd>> {
    let text = sandbox.read("/etc/passwd")?;
    Some(
        text.lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                (f.len() >= 7).then(|| Passwd {
                    name: f[0].to_string(),
                    uid: f[2].parse().unwrap_or(u32::MAX),
                    shell: f[6].to_string(),
                })
            })
            .collect(),
    )
}

/// `deny` in faillock.conf, or a PAM stack that mentions faillock or the
/// older tally modules.
fn lockout_configured(sandbox: &Sandbox) -> bool {
    let conf = sandbox
        .read("/etc/security/faillock.conf")
        .is_some_and(|text| {
            text.lines().map(str::trim).any(|l| {
                !l.starts_with('#')
                    && l.split_once('=')
                        .is_some_and(|(k, v)| k.trim() == "deny" && v.trim() != "0")
            })
        });
    let pam = sandbox.list("/etc/pam.d").iter().any(|name| {
        sandbox
            .read(&format!("/etc/pam.d/{name}"))
            .is_some_and(|text| {
                text.lines().map(str::trim).any(|l| {
                    !l.starts_with('#')
                        && (l.contains("pam_faillock")
                            || l.contains("pam_tally2")
                            || l.contains("pam_tally.so"))
                })
            })
    });
    // faillock.conf only matters when PAM loads the module; many distros
    // ship the module in their stack and tune it in the file.
    pam || conf && sandbox.exists("/usr/sbin/faillock")
}

/// `PASS_MAX_DAYS` from login.defs, parsed; `None` when unreadable or
/// absent (so the caller can say "cannot tell").
fn password_max_age(sandbox: &Sandbox) -> Option<i64> {
    let text = sandbox.read("/etc/login.defs")?;
    text.lines().find_map(|line| {
        let line = line.trim();
        (line.starts_with("PASS_MAX_DAYS")).then(|| {
            line.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<i64>().ok())
        })?
    })
}

/// Whether the inactive-account default is set to lock accounts (any
/// value but `-1`, which means "never").
fn inactive_set(sandbox: &Sandbox) -> Option<bool> {
    let text = sandbox.read("/etc/default/useradd")?;
    let value = text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("INACTIVE=").map(str::to_string)
    })?;
    Some(value.trim() != "-1")
}

/// The mode and owner a sensitive file must have, and whether they hold.
fn sensitive_perms(sandbox: &Sandbox, path: &str, want_mode: u32) -> Option<bool> {
    let (mode, uid, gid) = sandbox.metadata(path)?;
    Some(mode == want_mode && uid == 0 && gid == 0)
}

/// Whether sudo is configured to log what it runs (input, output or a
/// dedicated log file).
fn sudo_logging(sandbox: &Sandbox) -> Option<bool> {
    let mut texts = vec![sandbox.read("/etc/sudoers")?];
    for name in sandbox.list("/etc/sudoers.d") {
        if name.contains('.') || name.ends_with('~') {
            continue;
        }
        if let Some(text) = sandbox.read(&format!("/etc/sudoers.d/{name}")) {
            texts.push(text);
        }
    }
    Some(texts.iter().any(|text| {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && !l.starts_with("Defaults!"))
            .any(|l| l.contains("log_input") || l.contains("log_output") || l.contains("logfile"))
    }))
}

/// Whether any login banner (local console or sshd) is set.
fn login_banner(sandbox: &Sandbox) -> Option<bool> {
    if let Some(issue) = sandbox.read("/etc/issue")
        && !issue.trim().is_empty()
    {
        return Some(true);
    }
    if let Some(config) = sandbox.read("/etc/ssh/sshd_config") {
        let banner = config.lines().find_map(|line| {
            let line = line.trim();
            line.strip_prefix("Banner ")
                .map(str::trim)
                .map(str::to_string)
        });
        if let Some(path) = banner {
            if sandbox
                .read(&path)
                .is_some_and(|text| !text.trim().is_empty())
            {
                return Some(true);
            }
            return Some(false);
        }
    }
    // No /etc/issue and no sshd Banner: nothing we can confirm.
    None
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let mut results = Vec::new();
    let finding = |id: &str, severity, user: Option<&str>| {
        let mut args = BTreeMap::new();
        if let Some(user) = user {
            args.insert("user".to_string(), user.to_string());
        }
        Finding {
            id: match user {
                Some(user) => format!("accounts.{id}.{user}"),
                None => format!("accounts.{id}"),
            },
            plugin: "system.accounts".into(),
            severity,
            title_key: format!("accounts-{id}-title"),
            summary_key: format!("accounts-{id}-summary"),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        }
    };

    let users = passwd(sandbox);
    // Extra uid 0.
    let uid0 = match &users {
        None => CheckOutcome::NotAssessed,
        Some(users) => {
            let extra: Vec<&Passwd> = users
                .iter()
                .filter(|u| u.uid == 0 && u.name != "root")
                .collect();
            for user in &extra {
                findings.push(finding("uid0", Severity::High, Some(&user.name)));
            }
            if extra.is_empty() {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            }
        }
    };
    results.push(CheckResult {
        id: "accounts.uid0".into(),
        severity: Severity::High,
        outcome: uid0,
    });

    // Empty passwords: an empty shadow field on an account that can log in.
    let empty = match (&users, sandbox.read("/etc/shadow")) {
        (Some(users), Some(shadow)) => {
            let mut bad = 0;
            for line in shadow.lines() {
                let mut f = line.split(':');
                let (Some(name), Some(hash)) = (f.next(), f.next()) else {
                    continue;
                };
                if hash.is_empty() && users.iter().any(|u| u.name == name && can_login(&u.shell)) {
                    bad += 1;
                    findings.push(finding("empty", Severity::High, Some(name)));
                }
            }
            if bad == 0 {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            }
        }
        _ => CheckOutcome::NotAssessed,
    };
    results.push(CheckResult {
        id: "accounts.empty_passwords".into(),
        severity: Severity::High,
        outcome: empty,
    });

    // Lockout: without a readable PAM directory this cannot be judged.
    let lockout = if sandbox.list("/etc/pam.d").is_empty() {
        CheckOutcome::NotAssessed
    } else if lockout_configured(sandbox) {
        CheckOutcome::Pass
    } else {
        findings.push(finding("lockout", Severity::Low, None));
        CheckOutcome::Fail
    };
    results.push(CheckResult {
        id: "accounts.lockout".into(),
        severity: Severity::Low,
        outcome: lockout,
    });

    let simple = |id: &str, severity, arg: Option<(&str, String)>| {
        let mut args = BTreeMap::new();
        if let Some((key, value)) = arg {
            args.insert(key.to_string(), value);
        }
        Finding {
            id: format!("accounts.{id}"),
            plugin: "system.accounts".into(),
            severity,
            title_key: format!("accounts-{id}-title"),
            summary_key: format!("accounts-{id}-summary"),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        }
    };

    // A maximum password age is set (a real limit, not "never").
    let max_age = match password_max_age(sandbox) {
        Some(days) if (1..=365).contains(&days) => CheckOutcome::Pass,
        Some(_) => {
            findings.push(simple("password_max_age", Severity::Medium, None));
            CheckOutcome::Fail
        }
        None => CheckOutcome::NotAssessed,
    };
    results.push(CheckResult {
        id: "accounts.password_max_age".into(),
        severity: Severity::Medium,
        outcome: max_age,
    });

    // Accounts lock after inactivity (not "never").
    let inactive = match inactive_set(sandbox) {
        Some(true) => CheckOutcome::Pass,
        Some(false) => {
            findings.push(simple("inactive", Severity::Low, None));
            CheckOutcome::Fail
        }
        None => CheckOutcome::NotAssessed,
    };
    results.push(CheckResult {
        id: "accounts.inactive".into(),
        severity: Severity::Low,
        outcome: inactive,
    });

    // Sensitive files are root-owned with the expected mode.
    let file_perms = match [
        ("/etc/shadow", 0o600),
        ("/etc/passwd", 0o644),
        ("/etc/sudoers", 0o440),
    ]
    .into_iter()
    .map(|(path, want)| (path, sensitive_perms(sandbox, path, want)))
    .collect::<Vec<_>>()
    {
        values if values.iter().any(|(_, ok)| ok.is_none()) => CheckOutcome::NotAssessed,
        values if values.iter().all(|(_, ok)| ok == &Some(true)) => CheckOutcome::Pass,
        values => {
            for (path, ok) in &values {
                if ok == &Some(false) {
                    findings.push(simple(
                        "file_perms",
                        Severity::High,
                        Some(("file", path.to_string())),
                    ));
                }
            }
            CheckOutcome::Fail
        }
    };
    results.push(CheckResult {
        id: "accounts.file_perms".into(),
        severity: Severity::High,
        outcome: file_perms,
    });

    // sudo records what it runs.
    let sudo_log = match sudo_logging(sandbox) {
        Some(true) => CheckOutcome::Pass,
        Some(false) => {
            findings.push(simple("sudo_logging", Severity::Low, None));
            CheckOutcome::Fail
        }
        None => CheckOutcome::NotAssessed,
    };
    results.push(CheckResult {
        id: "accounts.sudo_logging".into(),
        severity: Severity::Low,
        outcome: sudo_log,
    });

    // A login banner is shown.
    let banner = match login_banner(sandbox) {
        Some(true) => CheckOutcome::Pass,
        Some(false) => {
            findings.push(simple("login_banner", Severity::Low, None));
            CheckOutcome::Fail
        }
        None => CheckOutcome::NotAssessed,
    };
    results.push(CheckResult {
        id: "accounts.login_banner".into(),
        severity: Severity::Low,
        outcome: banner,
    });

    CheckReport { results, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-acc-{}-{}",
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

    const PASSWD: &str = "root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/zsh\ntoor:x:0:0::/:/bin/sh\n";

    fn outcome(report: &CheckReport, id: &str) -> CheckOutcome {
        report.results.iter().find(|r| r.id == id).unwrap().outcome
    }

    #[test]
    fn empty_passwords_count_only_for_accounts_that_can_log_in() {
        let (root, sandbox) = tree(&[
            ("/etc/passwd", PASSWD),
            // daemon: empty but nologin (fine); alice: locked (!); bob: empty with zsh.
            (
                "/etc/shadow",
                "root:$6$x:1::::::\ndaemon::1::::::\nalice:!:1::::::\nbob::1::::::\n",
            ),
            (
                "/etc/pam.d/system-auth",
                "auth required pam_faillock.so preauth\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(
            outcome(&report, "accounts.empty_passwords"),
            CheckOutcome::Fail
        );
        let empties: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.id.starts_with("accounts.empty"))
            .map(|f| f.args["user"].as_str())
            .collect();
        assert_eq!(empties, ["bob"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_second_uid_zero_account_is_a_finding_named_by_user() {
        let (root, sandbox) = tree(&[("/etc/passwd", PASSWD), ("/etc/shadow", "root:!:1::::::\n")]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(outcome(&report, "accounts.uid0"), CheckOutcome::Fail);
        let f = report
            .findings
            .iter()
            .find(|f| f.id == "accounts.uid0.toor")
            .unwrap();
        assert_eq!(f.severity, Severity::High);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lockout_is_found_in_pam_or_in_faillock_conf_with_the_tool() {
        let base = [
            ("/etc/passwd", "root:x:0:0::/root:/bin/bash\n"),
            ("/etc/shadow", "root:!:1::::::\n"),
        ];
        let mut with = base.to_vec();
        with.push((
            "/etc/pam.d/login",
            "auth required pam_faillock.so authfail\n",
        ));
        let (root, sandbox) = tree(&with);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "accounts.lockout"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
        let mut without = base.to_vec();
        without.push(("/etc/pam.d/login", "auth required pam_unix.so\n"));
        let (root, sandbox) = tree(&without);
        let report = evaluate(&sandbox, "now");
        assert_eq!(outcome(&report, "accounts.lockout"), CheckOutcome::Fail);
        assert!(report.findings.iter().any(|f| f.id == "accounts.lockout"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unreadable_inputs_are_never_a_pass() {
        let (root, sandbox) = tree(&[("/etc/passwd", PASSWD)]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(
            outcome(&report, "accounts.empty_passwords"),
            CheckOutcome::NotAssessed
        );
        assert_eq!(
            outcome(&report, "accounts.lockout"),
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[]);
        assert!(
            evaluate(&sandbox, "now")
                .results
                .iter()
                .all(|r| r.outcome == CheckOutcome::NotAssessed)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_account_names_stay_arguments() {
        let (root, sandbox) = tree(&[
            (
                "/etc/passwd",
                "root:x:0:0::/root:/bin/bash\n<b>x</b>:x:0:0::/:/bin/sh\n",
            ),
            ("/etc/shadow", "root:!:1::::::\n"),
        ]);
        let report = evaluate(&sandbox, "now");
        let f = report
            .findings
            .iter()
            .find(|f| f.id.starts_with("accounts.uid0"))
            .unwrap();
        assert_eq!(f.args["user"], "<b>x</b>");
        assert!(!f.summary_key.contains('<'));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn password_age_and_inactivity_are_read_from_the_distro_files() {
        let (root, sandbox) = tree(&[
            ("/etc/login.defs", "PASS_MAX_DAYS\t90\n"),
            ("/etc/default/useradd", "INACTIVE=30\n"),
        ]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "accounts.password_max_age"),
            CheckOutcome::Pass
        );
        assert_eq!(outcome(&report, "accounts.inactive"), CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();

        // "never" for both means a password that never expires and
        // accounts that are never locked.
        let (root, sandbox) = tree(&[
            ("/etc/login.defs", "PASS_MAX_DAYS\t99999\n"),
            ("/etc/default/useradd", "INACTIVE=-1\n"),
        ]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "accounts.password_max_age"),
            CheckOutcome::Fail
        );
        assert_eq!(outcome(&report, "accounts.inactive"), CheckOutcome::Fail);
        std::fs::remove_dir_all(root).unwrap();

        // Unreadable files mean "cannot tell", never a pass.
        let (root, sandbox) = tree(&[]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "accounts.password_max_age"),
            CheckOutcome::NotAssessed
        );
        assert_eq!(
            outcome(&report, "accounts.inactive"),
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sensitive_files_and_sudo_logging_are_checked() {
        // Without the files, permissions cannot be judged.
        let (root, sandbox) = tree(&[]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "accounts.file_perms"),
            CheckOutcome::NotAssessed
        );
        assert_eq!(
            outcome(&report, "accounts.sudo_logging"),
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();

        // Files present but owned by the test user are a failure (the
        // real system expects root ownership).
        let (root, sandbox) = tree(&[
            ("/etc/shadow", "root:x:\n"),
            ("/etc/passwd", "root:x:0:0::/root:/bin/bash\n"),
            ("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n"),
        ]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(outcome(&report, "accounts.file_perms"), CheckOutcome::Fail);
        std::fs::remove_dir_all(root).unwrap();

        // sudo logging configured in a drop-in passes.
        let (root, sandbox) = tree(&[
            ("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n"),
            ("/etc/sudoers.d/logging", "Defaults log_output\n"),
        ]);
        let report = evaluate(&sandbox, "t");
        assert_eq!(
            outcome(&report, "accounts.sudo_logging"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_login_banner_is_detected_from_issue_or_sshd() {
        let (root, sandbox) = tree(&[("/etc/issue", "Authorized use only\n")]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "t"), "accounts.login_banner"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();

        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", "Banner /etc/ssh/banner\n"),
            ("/etc/ssh/banner", "Authorized use only\n"),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "t"), "accounts.login_banner"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();

        let (root, sandbox) = tree(&[]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "t"), "accounts.login_banner"),
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
