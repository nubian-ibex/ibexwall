// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.session-lock`: does the screen lock by itself? Read-only and
//! limited to what files say. KDE keeps its settings in each user's
//! `~/.config/kscreenlockerrc`; GNOME keeps them in dconf, where the
//! per-user database is binary: this plugin reads the system-wide dconf
//! defaults (`/etc/dconf/db/*.d`) and says "not assessed" for GNOME when
//! nothing there decides it, instead of calling the stock defaults a pass
//! (a user may have changed them). The session agent, which can ask
//! the desktop directly, is the way to close that gap.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

/// Minutes of inactivity after which a lock counts as slow.
const SLOW_MINUTES: u32 = 15;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(SessionLock)) {
        eprintln!("ibexwall-plugin-session-lock: {err}");
        std::process::exit(1);
    }
}

struct SessionLock;

impl Plugin for SessionLock {
    fn id(&self) -> &'static str {
        "system.session-lock"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}

/// `[section] key` from a key file, last assignment winning.
fn key(text: &str, section: &str, name: &str) -> Option<String> {
    let mut inside = false;
    let mut found = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = s == section;
        } else if inside
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == name
        {
            found = Some(v.trim().to_string());
        }
    }
    found
}

/// What one desktop's settings say: `Some(false)` locks never, `Some(true)`
/// locks after `minutes` (0 means "no idle timeout set").
#[derive(Debug, PartialEq, Eq)]
struct Setting {
    who: String,
    locks: bool,
    minutes: u32,
}

fn gnome_system(sandbox: &Sandbox) -> Option<Setting> {
    let mut locks = None;
    let mut idle = None;
    // Profiles are applied in `db` order; a later file wins.
    for db in sandbox.list("/etc/dconf/db") {
        if !db.ends_with(".d") {
            continue;
        }
        for file in sandbox.list(&format!("/etc/dconf/db/{db}")) {
            let Some(text) = sandbox.read(&format!("/etc/dconf/db/{db}/{file}")) else {
                continue;
            };
            if let Some(v) = key(&text, "org/gnome/desktop/screensaver", "lock-enabled") {
                locks = Some(v == "true");
            }
            if let Some(v) = key(&text, "org/gnome/desktop/session", "idle-delay") {
                idle = v.rsplit(' ').next().and_then(|n| n.parse::<u32>().ok());
            }
        }
    }
    if locks.is_none() && idle.is_none() {
        return None;
    }
    Some(Setting {
        who: "GNOME (system defaults)".into(),
        // GNOME's own defaults: lock enabled, blank after 5 minutes.
        locks: locks.unwrap_or(true) && idle != Some(0),
        minutes: idle.map(|s| s / 60).unwrap_or(5),
    })
}

fn kde_users(sandbox: &Sandbox) -> Vec<Setting> {
    sandbox
        .list("/home")
        .into_iter()
        .filter_map(|user| {
            let text = sandbox.read(&format!("/home/{user}/.config/kscreenlockerrc"))?;
            let autolock = key(&text, "Daemon", "Autolock")
                .map(|v| v == "true")
                .unwrap_or(true);
            let minutes = key(&text, "Daemon", "Timeout")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(5);
            Some(Setting {
                who: format!("KDE ({user})"),
                locks: autolock,
                minutes,
            })
        })
        .collect()
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let id = "session_lock.automatic";
    let has_gnome = sandbox.exists("/usr/bin/gnome-shell");
    let has_kde =
        sandbox.exists("/usr/bin/plasmashell") || sandbox.exists("/usr/bin/kscreenlocker_greet");
    let mut settings = Vec::new();
    if has_gnome {
        settings.extend(gnome_system(sandbox));
    }
    if has_kde {
        settings.extend(kde_users(sandbox));
    }
    let report = |outcome, findings| CheckReport {
        results: vec![CheckResult {
            id: id.into(),
            severity: Severity::Medium,
            outcome,
        }],
        findings,
    };
    if !has_gnome && !has_kde {
        return report(CheckOutcome::NotApplicable, vec![]);
    }
    if settings.is_empty() {
        return report(CheckOutcome::NotAssessed, vec![]);
    }
    let mut findings = Vec::new();
    for s in &settings {
        let (kind, severity) = if !s.locks {
            ("off", Severity::Medium)
        } else if s.minutes > SLOW_MINUTES {
            ("slow", Severity::Low)
        } else {
            continue;
        };
        let mut args = BTreeMap::new();
        args.insert("who".to_string(), s.who.clone());
        args.insert("minutes".to_string(), s.minutes.to_string());
        findings.push(Finding {
            id: format!("sessionlock.{kind}.{}", s.who),
            plugin: "system.session-lock".into(),
            severity,
            title_key: format!("sessionlock-{kind}-title"),
            summary_key: format!("sessionlock-{kind}-summary"),
            args,
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: detected_at.into(),
        });
    }
    report(
        if findings.is_empty() {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        },
        findings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-lock-{}-{}",
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

    const GNOME: (&str, &str) = ("/usr/bin/gnome-shell", "");
    const PLASMA: (&str, &str) = ("/usr/bin/plasmashell", "");

    fn outcome(sandbox: &Sandbox) -> CheckOutcome {
        evaluate(sandbox, "now").results[0].outcome
    }

    #[test]
    fn no_desktop_is_not_applicable_and_gnome_without_a_system_default_is_not_assessed() {
        let (root, sandbox) = tree(&[]);
        assert_eq!(outcome(&sandbox), CheckOutcome::NotApplicable);
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[GNOME]);
        assert_eq!(
            outcome(&sandbox),
            CheckOutcome::NotAssessed,
            "a user may have changed the stock defaults"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn gnome_system_defaults_are_judged() {
        let (root, sandbox) = tree(&[
            GNOME,
            (
                "/etc/dconf/db/local.d/00-lock",
                "[org/gnome/desktop/screensaver]\nlock-enabled=false\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings[0].title_key, "sessionlock-off-title");
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            GNOME,
            (
                "/etc/dconf/db/local.d/00-lock",
                "[org/gnome/desktop/session]\nidle-delay=uint32 1800\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.findings[0].title_key, "sessionlock-slow-title");
        assert_eq!(report.findings[0].args["minutes"], "30");
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            GNOME,
            (
                "/etc/dconf/db/local.d/00-lock",
                "[org/gnome/desktop/session]\nidle-delay=uint32 300\n[org/gnome/desktop/screensaver]\nlock-enabled=true\n",
            ),
        ]);
        assert_eq!(outcome(&sandbox), CheckOutcome::Pass);
        std::fs::remove_dir_all(root).unwrap();
        // An idle delay of zero never blanks, so never locks.
        let (root, sandbox) = tree(&[
            GNOME,
            (
                "/etc/dconf/db/local.d/00-lock",
                "[org/gnome/desktop/session]\nidle-delay=uint32 0\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").findings[0].title_key,
            "sessionlock-off-title"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kde_settings_are_read_per_user() {
        let (root, sandbox) = tree(&[
            PLASMA,
            (
                "/home/ana/.config/kscreenlockerrc",
                "[Daemon]\nAutolock=false\n",
            ),
            (
                "/home/bia/.config/kscreenlockerrc",
                "[Daemon]\nTimeout=45\n",
            ),
            (
                "/home/caio/.config/kscreenlockerrc",
                "[Daemon]\nAutolock=true\nTimeout=5\n",
            ),
            ("/home/dani/other", ""),
        ]);
        let report = evaluate(&sandbox, "now");
        let titles: Vec<String> = report
            .findings
            .iter()
            .map(|f| format!("{}:{}", f.title_key, f.args["who"]))
            .collect();
        assert_eq!(
            titles,
            [
                "sessionlock-off-title:KDE (ana)",
                "sessionlock-slow-title:KDE (bia)"
            ]
        );
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        std::fs::remove_dir_all(root).unwrap();
    }
}
