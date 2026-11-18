// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.ssh`: the SSH server's settings. The check reads
//! `/etc/ssh/sshd_config` and the files it includes with sshd's own
//! rules for the global scope (the first value of a keyword wins, parsing
//! stops at the first `Match`), so the plugin runs nothing and needs no
//! root. The control writes one owned drop-in named to sort first, then
//! has sshd validate the whole configuration (`sshd -t`) and restarts the
//! service, which keeps existing sessions; if validation fails the engine
//! rolls the file back.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-ibexwall.conf";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Ssh)) {
        eprintln!("ibexwall-plugin-ssh: {err}");
        std::process::exit(1);
    }
}

struct Ssh;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Also turn password sign-in off. Off by default: it locks out anyone
    /// without a key.
    pub password_auth: Option<bool>,
    /// Turn passwords off even though no authorized key was found. The
    /// plugin cannot read `~/.ssh` where the AppArmor profile denies it
    /// (Ubuntu, Debian), so a machine that does have keys looks like one
    /// that has none; this says the person checked.
    pub confirm_keys: bool,
}

impl Plugin for Ssh {
    fn id(&self) -> &'static str {
        "system.ssh"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }

    async fn verify(&self, _transaction: &str, ops: &[Op]) -> bool {
        verify(&Sandbox::system(), ops)
    }
}

/// Re-reads what sshd would use and checks it matches every directive the
/// drop-in wrote: a drop-in that exists but loses to an earlier setting
/// would otherwise pass as applied.
pub fn verify(sandbox: &Sandbox, ops: &[Op]) -> bool {
    let Some(settings) = effective(sandbox) else {
        return false;
    };
    ops.iter().all(|op| match op {
        Op::FileWrite { path, content, .. } if path == DROP_IN => content
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .all(|l| {
                let Some((key, want)) = l.split_once(' ') else {
                    return true;
                };
                settings
                    .get(&key.to_ascii_lowercase())
                    .is_some_and(|got| got.eq_ignore_ascii_case(want))
            }),
        _ => true,
    })
}

/// The directives of the global scope in the order sshd reads them,
/// following `Include`. Keywords are case-insensitive; the result keeps the
/// first value of each, as sshd does. `None` when the main file is missing
/// or an `Include` uses a pattern this reader cannot expand (guessing would
/// judge a configuration it did not read).
pub fn effective(sandbox: &Sandbox) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut unsupported = false;
    read_file(
        sandbox,
        "/etc/ssh/sshd_config",
        &mut out,
        &mut unsupported,
        0,
    )?;
    (!unsupported).then_some(out)
}

fn read_file(
    sandbox: &Sandbox,
    path: &str,
    out: &mut BTreeMap<String, String>,
    unsupported: &mut bool,
    depth: u8,
) -> Option<()> {
    let text = sandbox.read(path)?;
    // A Match line ends the global scope of this file only: an included
    // file's Match does not stop the includer's later settings.
    let mut stopped = false;
    for line in text.lines() {
        if stopped {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, value) = line
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .map(|(k, v)| {
                (
                    k.to_ascii_lowercase(),
                    v.trim().trim_matches('"').to_string(),
                )
            })
            .unwrap_or((line.to_ascii_lowercase(), String::new()));
        match keyword.as_str() {
            // Settings after a Match line are conditional: not global.
            "match" => stopped = true,
            "include" if depth < 4 => {
                for pattern in value.split_whitespace() {
                    match expand(sandbox, pattern) {
                        Some(files) => {
                            for file in files {
                                read_file(sandbox, &file, out, unsupported, depth + 1);
                            }
                        }
                        None => *unsupported = true,
                    }
                }
            }
            _ => {
                out.entry(keyword).or_insert(value);
            }
        }
    }
    Some(())
}

/// `Include` with a relative path is under `/etc/ssh`. The file name may use
/// `*`, `?` and `[...]` (sorted, as sshd's glob returns them); a wildcard in
/// a directory part is not supported and gives `None`.
fn expand(sandbox: &Sandbox, pattern: &str) -> Option<Vec<String>> {
    let absolute = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/etc/ssh/{pattern}")
    };
    let (dir, name) = absolute.rsplit_once('/')?;
    if dir.contains(['*', '?', '[']) {
        return None;
    }
    if !name.contains(['*', '?', '[']) {
        return Some(vec![absolute]);
    }
    Some(
        sandbox
            .list(dir)
            .into_iter()
            .filter(|entry| glob_match(name.as_bytes(), entry.as_bytes()))
            .map(|entry| format!("{dir}/{entry}"))
            .collect(),
    )
}

/// fnmatch subset: `*`, `?`, `[abc]`, `[a-z]` and `[!x]`.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some(b'*') => (0..=text.len()).any(|i| glob_match(&pattern[1..], &text[i..])),
        Some(b'?') => !text.is_empty() && glob_match(&pattern[1..], &text[1..]),
        Some(b'[') => {
            let Some(end) = pattern
                .iter()
                .skip(2)
                .position(|&c| c == b']')
                .map(|i| i + 2)
            else {
                return !text.is_empty()
                    && text[0] == b'['
                    && glob_match(&pattern[1..], &text[1..]);
            };
            let Some(&c) = text.first() else {
                return false;
            };
            let set = &pattern[1..end];
            let (negate, set) = match set.first() {
                Some(b'!' | b'^') => (true, &set[1..]),
                _ => (false, set),
            };
            let mut hit = false;
            let mut i = 0;
            while i < set.len() {
                if i + 2 < set.len() && set[i + 1] == b'-' {
                    hit |= (set[i]..=set[i + 2]).contains(&c);
                    i += 3;
                } else {
                    hit |= set[i] == c;
                    i += 1;
                }
            }
            hit != negate && glob_match(&pattern[end + 1..], &text[1..])
        }
        Some(&p) => !text.is_empty() && text[0] == p && glob_match(&pattern[1..], &text[1..]),
    }
}

/// Whether a setting equals `want`, ignoring case (sshd does).
fn is(settings: &BTreeMap<String, String>, key: &str, default: &str, want: &str) -> bool {
    value(settings, key, default).eq_ignore_ascii_case(want)
}

fn value<'a>(settings: &'a BTreeMap<String, String>, key: &str, default: &'a str) -> &'a str {
    settings.get(key).map(String::as_str).unwrap_or(default)
}

/// What the machine does with SSH today, said before anything changes.
pub fn survey(settings: Option<&BTreeMap<String, String>>, at: &str) -> Finding {
    let mut args = BTreeMap::new();
    let mut patch = None;
    let case = match settings {
        None => "absent",
        Some(settings) => {
            let root = value(settings, "permitrootlogin", "prohibit-password");
            let empty = is(settings, "permitemptypasswords", "no", "yes");
            let x11 = is(settings, "x11forwarding", "no", "yes");
            let password = value(settings, "passwordauthentication", "yes");
            args.insert("root".into(), root.to_string());
            args.insert("password".into(), password.to_string());
            args.insert("port".into(), value(settings, "port", "22").to_string());
            if root.eq_ignore_ascii_case("yes") || empty || x11 {
                // The default plan closes root login, empty passwords and X11
                // forwarding; it keeps password sign-in, which needs a key first.
                patch = Some(serde_json::json!({}));
                "weak"
            } else if password.eq_ignore_ascii_case("yes") {
                "hardened-password"
            } else {
                "hardened"
            }
        }
    };
    ibexwall_sdk::detect::detected("system.ssh", "ssh", case, args, patch, at)
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let settings = effective(sandbox);
    let mut report = evaluate_settings(sandbox, settings.as_ref(), detected_at);
    report.findings.push(survey(settings.as_ref(), detected_at));
    report
}

fn evaluate_settings(
    sandbox: &Sandbox,
    settings: Option<&BTreeMap<String, String>>,
    detected_at: &str,
) -> CheckReport {
    let Some(settings) = settings else {
        // No sshd_config: no SSH server to judge.
        let outcome = if sandbox.exists("/usr/sbin/sshd") {
            CheckOutcome::NotAssessed
        } else {
            CheckOutcome::NotApplicable
        };
        return CheckReport {
            results: vec![CheckResult {
                id: "ssh.hardening".into(),
                severity: Severity::Medium,
                outcome,
            }],
            findings: vec![],
        };
    };
    let root = value(settings, "permitrootlogin", "prohibit-password");
    let root_yes = root.eq_ignore_ascii_case("yes");
    let empty = is(settings, "permitemptypasswords", "no", "yes");
    let x11 = is(settings, "x11forwarding", "no", "yes");
    let any_scored = root_yes || empty || x11;
    let mut findings = Vec::new();
    let mut add =
        |id: &str, severity, args: BTreeMap<String, String>, template: bool, may: &[&str]| {
            findings.push(Finding {
                id: format!("ssh.{id}"),
                plugin: "system.ssh".into(),
                severity,
                title_key: format!("ssh-{id}-title"),
                summary_key: format!("ssh-{id}-summary"),
                args,
                references: vec![],
                remediation: template.then(|| Remediation {
                    plan_template: Some("ssh.harden".into()),
                    may_affect_keys: may.iter().map(|s| s.to_string()).collect(),
                }),
                status: FindingStatus::Open,
                detected_at: detected_at.into(),
            });
        };
    if root_yes {
        let mut args = BTreeMap::new();
        args.insert("value".to_string(), root.to_string());
        add("root", Severity::High, args, true, &["ssh-may-affect-root"]);
    }
    if empty {
        add("empty", Severity::High, BTreeMap::new(), true, &[]);
    }
    if x11 {
        add("x11", Severity::Low, BTreeMap::new(), true, &[]);
    }
    // Password sign-in is informational: turning it off needs a key, so the
    // finding offers the plan but does not count against the score.
    if is(settings, "passwordauthentication", "yes", "yes") {
        add(
            "password",
            Severity::Info,
            BTreeMap::new(),
            true,
            &["ssh-may-affect-password"],
        );
    }
    CheckReport {
        results: vec![CheckResult {
            id: "ssh.hardening".into(),
            severity: Severity::Medium,
            outcome: if any_scored {
                CheckOutcome::Fail
            } else {
                CheckOutcome::Pass
            },
        }],
        findings,
    }
}

/// Whether some account that can log in has at least one key in its
/// authorized-keys file(s), honoring `AuthorizedKeysFile`. A configured
/// `AuthorizedKeysCommand` counts as usable (its output cannot be read here).
fn has_authorized_key(sandbox: &Sandbox, settings: &BTreeMap<String, String>) -> bool {
    let command = value(settings, "authorizedkeyscommand", "none");
    if !command.eq_ignore_ascii_case("none") && !command.is_empty() {
        return true;
    }
    let files = value(
        settings,
        "authorizedkeysfile",
        ".ssh/authorized_keys .ssh/authorized_keys2",
    );
    if files.eq_ignore_ascii_case("none") {
        return false;
    }
    let root_allowed = !is(settings, "permitrootlogin", "prohibit-password", "no");
    let Some(passwd) = sandbox.read("/etc/passwd") else {
        return false;
    };
    passwd.lines().any(|line| {
        let f: Vec<&str> = line.split(':').collect();
        let [name, _, uid, _, _, home, shell, ..] = f[..] else {
            return false;
        };
        let Ok(uid) = uid.parse::<u32>() else {
            return false;
        };
        let can_log_in = !shell.ends_with("/nologin") && !shell.ends_with("/false");
        if !can_log_in || !(uid >= 1000 || uid == 0 && root_allowed) {
            return false;
        }
        files.split_whitespace().any(|template| {
            let expanded = template
                .replace("%%", "\u{0}")
                .replace("%h", home)
                .replace("%u", name)
                .replace('\u{0}', "%");
            let path = if expanded.starts_with('/') {
                expanded
            } else {
                format!("{home}/{expanded}")
            };
            sandbox.read(&path).is_some_and(|text| {
                text.lines()
                    .map(str::trim)
                    .any(|l| !l.is_empty() && !l.starts_with('#'))
            })
        })
    })
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let main = sandbox.read("/etc/ssh/sshd_config").ok_or_else(|| {
        PluginError::invalid("config", "there is no /etc/ssh/sshd_config".to_string())
    })?;
    // First value wins, so the drop-in only takes effect when sshd reads
    // the drop-in directory before it reads its own settings.
    let include_before_settings = main
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find(|l| {
            let lower = l.to_ascii_lowercase();
            !lower.starts_with("include")
        })
        .is_none_or(|_| {
            main.lines().map(str::trim).any(|l| {
                l.to_ascii_lowercase().starts_with("include") && l.contains("sshd_config.d")
            }) && {
                let first_directive = main
                    .lines()
                    .map(str::trim)
                    .position(|l| !l.is_empty() && !l.starts_with('#'));
                let include_at = main.lines().map(str::trim).position(|l| {
                    l.to_ascii_lowercase().starts_with("include") && l.contains("sshd_config.d")
                });
                matches!((first_directive, include_at), (Some(a), Some(b)) if b <= a)
            }
        });
    if !include_before_settings {
        return Err(PluginError::invalid(
            "config",
            "sshd_config does not read /etc/ssh/sshd_config.d before its own settings, so a drop-in could not take effect".to_string(),
        ));
    }
    let current = effective(sandbox).ok_or_else(|| {
        PluginError::invalid(
            "config",
            "the sshd configuration uses an Include pattern that cannot be read".to_string(),
        )
    })?;
    let mut lines = vec!["# Managed by IbexWall (system.ssh).".to_string()];
    if is(&current, "permitrootlogin", "prohibit-password", "yes") {
        lines.push("PermitRootLogin prohibit-password".into());
    }
    if is(&current, "permitemptypasswords", "no", "yes") {
        lines.push("PermitEmptyPasswords no".into());
    }
    if is(&current, "x11forwarding", "no", "yes") {
        lines.push("X11Forwarding no".into());
    }
    if config.password_auth == Some(false) {
        // Without a key that can sign in, turning passwords off locks the
        // person out of new logins (a password-only VPS, for instance).
        if !config.confirm_keys && !has_authorized_key(sandbox, &current) {
            return Err(PluginError::invalid(
                "password_auth",
                "no usable authorized key was found, so turning passwords off could lock out new logins; add a key first (where the system hides ~/.ssh from this plugin, check by hand and set confirm_keys=true)".to_string(),
            ));
        }
        lines.push("PasswordAuthentication no".into());
        // Keyboard-interactive would still ask for the account password.
        lines.push("KbdInteractiveAuthentication no".into());
    }
    if lines.len() == 1 {
        return Err(PluginError::invalid(
            "config",
            "nothing to change: the settings already meet the reference".to_string(),
        ));
    }
    let unit = if sandbox.exists("/usr/lib/systemd/system/sshd.service")
        || sandbox.exists("/etc/systemd/system/sshd.service")
    {
        "sshd.service"
    } else {
        "ssh.service"
    };
    let mut ops = vec![
        Op::FileWrite {
            path: DROP_IN.into(),
            content: lines.join("\n") + "\n",
            mode: "0600".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        // The whole configuration, checked by sshd itself, before it is
        // restarted: a failure aborts and rolls the file back.
        Op::Exec {
            path: "/usr/sbin/sshd".into(),
            args: vec!["-t".into()],
        },
    ];
    // Restart only a running server (a stopped one stays stopped); a
    // restart keeps the existing sessions.
    if sandbox.exists("/run/sshd.pid") {
        ops.push(Op::SystemdUnit {
            unit: unit.into(),
            action: UnitAction::Restart,
            now: None,
        });
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-ssh-{}-{}",
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

    const INCLUDE_FIRST: &str = "Include /etc/ssh/sshd_config.d/*.conf\n# comment\nX11Forwarding yes\nPermitRootLogin yes\n";

    #[test]
    fn the_first_value_wins_across_includes_and_match_blocks_are_not_global() {
        let (root, sandbox) = tree(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User bob\n  PermitRootLogin no\n  X11Forwarding yes\n",
            ),
            (
                "/etc/ssh/sshd_config.d/10-a.conf",
                "permitrootlogin=prohibit-password\n",
            ),
        ]);
        let settings = effective(&sandbox).unwrap();
        assert_eq!(settings["permitrootlogin"], "prohibit-password");
        assert!(
            !settings.contains_key("x11forwarding"),
            "after Match is conditional"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn findings_follow_the_effective_values_and_defaults() {
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", INCLUDE_FIRST)]);
        let report = evaluate(&sandbox, "now");
        let ids: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .filter(|id| !id.starts_with("detect."))
            .collect();
        assert_eq!(ids, ["ssh.root", "ssh.x11", "ssh.password"]);
        let note = report
            .findings
            .iter()
            .find(|f| f.id == "detect.ssh")
            .unwrap();
        assert_eq!(note.summary_key, "detect-ssh-weak");
        assert_eq!(
            note.args["patch"], "{}",
            "the default change closes the risky settings"
        );
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].severity, Severity::High);
        std::fs::remove_dir_all(root).unwrap();
        // Defaults only: password sign-in alone is informational.
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", "# nothing set\n")]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Pass);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["ssh.password", "detect.ssh"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_server_is_not_applicable_and_an_unreadable_one_is_not_a_pass() {
        let (root, sandbox) = tree(&[]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotApplicable
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[("/usr/sbin/sshd", "")]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_writes_only_what_differs_validates_and_restarts_a_running_server() {
        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", INCLUDE_FIRST),
            ("/usr/lib/systemd/system/sshd.service", ""),
            ("/run/sshd.pid", "1\n"),
            ("/etc/passwd", "alice:x:1000:1000::/home/alice:/bin/bash\n"),
            ("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA a\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        let Op::FileWrite {
            path,
            content,
            mode,
            ..
        } = &ops[0]
        else {
            panic!()
        };
        assert_eq!(path, DROP_IN);
        assert_eq!(mode, "0600");
        assert!(content.contains("PermitRootLogin prohibit-password"));
        assert!(content.contains("X11Forwarding no"));
        assert!(!content.contains("PasswordAuthentication"), "opt-in only");
        assert!(
            matches!(&ops[1], Op::Exec { path, args } if path == "/usr/sbin/sshd" && args == &["-t"])
        );
        assert!(
            matches!(&ops[2], Op::SystemdUnit { unit, action: UnitAction::Restart, .. } if unit == "sshd.service")
        );
        let ops = plan(
            &sandbox,
            &Config {
                password_auth: Some(false),
                ..Config::default()
            },
        )
        .unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        assert!(content.contains("PasswordAuthentication no"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn values_are_compared_ignoring_case() {
        let (root, sandbox) = tree(&[(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin Yes\nX11Forwarding YES\n",
        )]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"ssh.root") && ids.contains(&"ssh.x11"));
        let Op::FileWrite { content, .. } = &plan(&sandbox, &Config::default()).unwrap()[0] else {
            panic!()
        };
        assert!(content.contains("PermitRootLogin prohibit-password"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_match_in_an_included_file_does_not_hide_the_main_files_settings() {
        let (root, sandbox) = tree(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
            ),
            (
                "/etc/ssh/sshd_config.d/10-a.conf",
                "Match User bob\n  X11Forwarding yes\n",
            ),
        ]);
        assert_eq!(effective(&sandbox).unwrap()["permitrootlogin"], "yes");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn include_globs_with_classes_are_expanded_and_directory_wildcards_refused() {
        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", "Include conf.d/[0-9]*.conf\n"),
            ("/etc/ssh/conf.d/10-a.conf", "PermitRootLogin yes\n"),
            ("/etc/ssh/conf.d/zz.conf", "X11Forwarding yes\n"),
        ]);
        let settings = effective(&sandbox).unwrap();
        assert_eq!(settings["permitrootlogin"], "yes");
        assert!(!settings.contains_key("x11forwarding"));
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", "Include /etc/*/ssh.conf\n")]);
        assert!(
            effective(&sandbox).is_none(),
            "unreadable config is not judged"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn turning_passwords_off_needs_a_key_and_also_closes_keyboard_interactive() {
        let config = Config {
            password_auth: Some(false),
            ..Config::default()
        };
        let base = [
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
            ),
            (
                "/etc/passwd",
                "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbot:x:1001:1001::/home/bot:/usr/sbin/nologin\n",
            ),
        ];
        // No keys anywhere: refused.
        let (root, sandbox) = tree(&base);
        let error = plan(&sandbox, &config).unwrap_err();
        assert!(error.to_string().contains("authorized key"));
        // Where the system hides ~/.ssh from the plugin, the person says
        // they checked.
        let confirmed = Config {
            confirm_keys: true,
            ..Config::default()
        };
        let confirmed = Config {
            password_auth: Some(false),
            ..confirmed
        };
        assert!(plan(&sandbox, &confirmed).is_ok());
        std::fs::remove_dir_all(root).unwrap();
        // A key only for a nologin account does not count; a comment neither.
        let mut files = base.to_vec();
        files.push(("/home/bot/.ssh/authorized_keys", "ssh-ed25519 AAAA bot\n"));
        files.push(("/home/alice/.ssh/authorized_keys", "# nothing yet\n"));
        let (root, sandbox) = tree(&files);
        assert!(plan(&sandbox, &config).is_err());
        std::fs::remove_dir_all(root).unwrap();
        // A real key for a login account: allowed, with both directives.
        let mut files = base.to_vec();
        files.push((
            "/home/alice/.ssh/authorized_keys",
            "ssh-ed25519 AAAA alice\n",
        ));
        let (root, sandbox) = tree(&files);
        let ops = plan(&sandbox, &config).unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        assert!(content.contains("PasswordAuthentication no"));
        assert!(content.contains("KbdInteractiveAuthentication no"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verify_rereads_the_effective_configuration() {
        let drop_in = |content: &str| {
            vec![Op::FileWrite {
                path: DROP_IN.into(),
                content: content.into(),
                mode: "0600".into(),
                owner: "root".into(),
                group: "root".into(),
            }]
        };
        let ops = drop_in("# Managed\nPermitRootLogin prohibit-password\n");
        let (root, applied) = tree(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
            ),
            (DROP_IN, "PermitRootLogin prohibit-password\n"),
        ]);
        assert!(verify(&applied, &ops));
        std::fs::remove_dir_all(root).unwrap();
        // The file exists but an earlier setting wins: not applied.
        let (root, shadowed) = tree(&[
            (
                "/etc/ssh/sshd_config",
                "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n",
            ),
            (DROP_IN, "PermitRootLogin prohibit-password\n"),
        ]);
        assert!(!verify(&shadowed, &ops));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stopped_server_is_not_started_and_the_debian_unit_name_is_used() {
        let (root, sandbox) = tree(&[("/etc/ssh/sshd_config", INCLUDE_FIRST)]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert_eq!(ops.len(), 2, "no restart for a server that is not running");
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            ("/etc/ssh/sshd_config", INCLUDE_FIRST),
            ("/run/sshd.pid", "1\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert!(matches!(&ops[2], Op::SystemdUnit { unit, .. } if unit == "ssh.service"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_drop_in_that_could_not_take_effect_is_refused() {
        // Settings come before the Include: first value wins, so ours would lose.
        let (root, sandbox) = tree(&[(
            "/etc/ssh/sshd_config",
            "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n",
        )]);
        let error = plan(&sandbox, &Config::default()).unwrap_err();
        assert!(error.to_string().contains("before its own settings"));
        std::fs::remove_dir_all(root).unwrap();
        // Nothing to change.
        let (root, sandbox) = tree(&[(
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )]);
        assert!(
            plan(&sandbox, &Config::default())
                .unwrap_err()
                .to_string()
                .contains("nothing to change")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_note_tells_a_missing_server_a_weak_one_and_a_hardened_one_with_and_without_passwords() {
        let (r1, none) = tree(&[]);
        assert_eq!(
            survey(effective(&none).as_ref(), "x").summary_key,
            "detect-ssh-absent"
        );
        let (r2, weak) = tree(&[("/etc/ssh/sshd_config", "PermitRootLogin yes\nPort 2222\n")]);
        let note = survey(effective(&weak).as_ref(), "x");
        assert_eq!(
            (
                note.summary_key.as_str(),
                note.args["port"].as_str(),
                note.args["root"].as_str()
            ),
            ("detect-ssh-weak", "2222", "yes")
        );
        let (r3, pw) = tree(&[("/etc/ssh/sshd_config", "PermitRootLogin no\n")]);
        let note = survey(effective(&pw).as_ref(), "x");
        assert_eq!(note.summary_key, "detect-ssh-hardened-password");
        assert!(
            !note.args.contains_key("patch"),
            "password sign-in is never switched off for the person"
        );
        let (r4, tight) = tree(&[(
            "/etc/ssh/sshd_config",
            "PermitRootLogin no\nPasswordAuthentication no\n",
        )]);
        assert_eq!(
            survey(effective(&tight).as_ref(), "x").summary_key,
            "detect-ssh-hardened"
        );
        for r in [r1, r2, r3, r4] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }
}
