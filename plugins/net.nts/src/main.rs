// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.nts`: is the clock set by servers it can authenticate? chrony with
//! NTS (RFC 8915). The check reads chrony's configuration the way chrony
//! does (main file, `confdir`, `sourcedir`) and passes when at least one
//! source carries the `nts` option. The control adds the servers of a
//! chosen preset, never editing the distro's file and never installing
//! chrony, through a per-distro adapter:
//!
//! - Debian and Ubuntu name a `confdir` (`/etc/chrony/conf.d`): one owned
//!   drop-in there.
//! - Fedora and Arch name none, so there is nowhere to drop a file chrony
//!   would read. The adapter then writes an owned configuration that
//!   `include`s the distro's own file and adds the servers
//!   (`/etc/chrony-ibexwall/chrony.conf`), and an owned systemd drop-in that
//!   starts chronyd with `-f` pointing at it.
//!
//! Either way chrony is restarted afterwards.
//!
//! That the servers really authenticate (`chronyc -N authdata`) is proved
//! on a real machine in the F7 VM phase, not guessed here.

mod detect;

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

/// Providers whose servers speak NTS (RFC 8915). Hostnames from the
/// providers' own documentation: Cloudflare (time.cloudflare.com), Netnod
/// (nts.netnod.se), PTB (ptbtime1.ptb.de, ptbtime2.ptb.de) and NTP.br
/// (a.st1.ntp.br, b.st1.ntp.br; ntp.br lists them with NTS in its own
/// examples).
pub const PRESETS: &[(&str, &[&str])] = &[
    ("cloudflare", &["time.cloudflare.com"]),
    ("netnod", &["nts.netnod.se"]),
    ("ptb", &["ptbtime1.ptb.de", "ptbtime2.ptb.de"]),
    ("ntpbr", &["a.st1.ntp.br", "b.st1.ntp.br"]),
];

const WRAPPER_CONF: &str = "/etc/chrony-ibexwall/chrony.conf";
const WRAPPER_UNIT_DROP_IN: &str = "/etc/systemd/system/chronyd.service.d/70-ibexwall-nts.conf";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Nts)) {
        eprintln!("ibexwall-plugin-nts: {err}");
        std::process::exit(1);
    }
}

struct Nts;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// One of the presets, comma-separated for several.
    pub preset: Option<String>,
    /// Extra NTS servers by name, comma-separated.
    pub servers: Option<String>,
}

impl Plugin for Nts {
    fn id(&self) -> &'static str {
        "net.nts"
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

fn chrony_installed(sandbox: &Sandbox) -> bool {
    sandbox.exists("/usr/sbin/chronyd") || sandbox.exists("/usr/bin/chronyd")
}

fn chronyd_running(sandbox: &Sandbox) -> bool {
    // The same probe the plan uses to decide whether to restart chronyd.
    sandbox.exists("/run/chrony/chronyd.pid") || sandbox.exists("/run/chronyd.pid")
}

/// Whether systemd-timesyncd has synchronized the clock (its marker file).
fn timesyncd_synchronized(sandbox: &Sandbox) -> bool {
    sandbox.exists("/run/systemd/timesync/synchronized")
}

fn main_config(sandbox: &Sandbox) -> Option<(&'static str, String)> {
    ["/etc/chrony.conf", "/etc/chrony/chrony.conf"]
        .into_iter()
        .find_map(|path| sandbox.read(path).map(|text| (path, text)))
}

/// The value of the last `confdir` / `sourcedir` directive, as chrony
/// takes it (the first path, glob-free).
fn directive(text: &str, name: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with('!') && !l.starts_with(';'))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == name).then(|| words.next().map(str::to_string))?
        })
        .next_back()
}

/// Every source line (`server`, `pool`, `peer`) with whether it uses NTS,
/// from the main file and the directories it names.
fn sources(sandbox: &Sandbox) -> Option<Vec<(String, bool)>> {
    let (_, main) = main_config(sandbox)?;
    let mut texts = vec![main.clone()];
    // The wrapper counts only while the service drop-in that makes chronyd
    // read it is in place.
    if sandbox.exists(WRAPPER_UNIT_DROP_IN)
        && let Some(text) = sandbox.read(WRAPPER_CONF)
    {
        texts.push(text);
    }
    for (name, extension) in [("confdir", ".conf"), ("sourcedir", ".sources")] {
        if let Some(dir) = directive(&main, name) {
            for file in sandbox.list(&dir) {
                if file.ends_with(extension)
                    && let Some(text) = sandbox.read(&format!("{dir}/{file}"))
                {
                    texts.push(text);
                }
            }
        }
    }
    let mut out = Vec::new();
    for text in texts {
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with('!') || line.starts_with(';') {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if matches!(words.first(), Some(&"server" | &"pool" | &"peer")) && words.len() >= 2 {
                out.push((words[1].to_string(), words[2..].contains(&"nts")));
            }
        }
    }
    Some(out)
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let finding = |kind: &str, remediation: Option<Remediation>| Finding {
        id: format!("nts.{kind}"),
        plugin: "net.nts".into(),
        severity: Severity::Medium,
        title_key: format!("nts-{kind}-title"),
        summary_key: format!("nts-{kind}-summary"),
        args: BTreeMap::new(),
        references: vec![],
        remediation,
        status: FindingStatus::Open,
        detected_at: detected_at.into(),
    };
    let mut findings = Vec::new();
    let outcome = if !chrony_installed(sandbox) {
        findings.push(finding("missing", None));
        CheckOutcome::Fail
    } else {
        match sources(sandbox) {
            None => CheckOutcome::NotAssessed,
            Some(list) if list.iter().any(|(_, nts)| *nts) => {
                // An NTS source only protects the clock if chronyd is
                // actually running; a stopped or disabled chronyd leaves
                // the clock to unauthenticated time, so never claim Pass
                // from the config alone.
                if chronyd_running(sandbox) {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::NotAssessed
                }
            }
            Some(_) => {
                findings.push(finding(
                    "off",
                    Some(Remediation {
                        plan_template: Some("nts.enable".into()),
                        may_affect_keys: vec![
                            "nts-may-affect-firewall-4460".into(),
                            "nts-may-affect-clock".into(),
                        ],
                    }),
                ));
                CheckOutcome::Fail
            }
        }
    };
    // After the problems, so they keep their place: what is found today.
    findings.push(detect::time(sandbox, detected_at));
    CheckReport {
        results: vec![
            CheckResult {
                id: "nts.authenticated_time".into(),
                severity: Severity::Medium,
                outcome,
            },
            // Synchronized at all (not necessarily authenticated): a pass
            // only with positive evidence, otherwise not-assessed.
            CheckResult {
                id: "nts.synchronized".into(),
                severity: Severity::Medium,
                outcome: if chronyd_running(sandbox) || timesyncd_synchronized(sandbox) {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::NotAssessed
                },
            },
        ],
        findings,
    }
}

fn valid_host(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && !host.starts_with(['-', '.'])
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    if !chrony_installed(sandbox) {
        return Err(PluginError::invalid(
            "config",
            "chrony is not installed; IbexWall does not install software by itself".to_string(),
        ));
    }
    let mut hosts: Vec<String> = Vec::new();
    for name in config
        .preset
        .as_deref()
        .unwrap_or("cloudflare")
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        let (_, list) = PRESETS
            .iter()
            .find(|(preset, _)| *preset == name)
            .ok_or_else(|| {
                PluginError::invalid(
                    "preset",
                    format!("`{name}`: choose cloudflare, netnod, ptb or ntpbr"),
                )
            })?;
        hosts.extend(list.iter().map(|h| h.to_string()));
    }
    for host in config
        .servers
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
    {
        if !valid_host(&host) {
            return Err(PluginError::invalid(
                "servers",
                format!("`{host}` is not a host name"),
            ));
        }
        hosts.push(host);
    }
    hosts.dedup();

    let (main_path, main) = main_config(sandbox)
        .ok_or_else(|| PluginError::invalid("config", "there is no chrony.conf".to_string()))?;
    // Debian and Ubuntu ship `chrony.service` and only alias it as
    // chronyd.service from /etc; the real unit file decides.
    let unit = if sandbox.exists("/usr/lib/systemd/system/chronyd.service") {
        "chronyd.service"
    } else {
        "chrony.service"
    };
    let servers: String = hosts
        .iter()
        .map(|host| format!("server {host} iburst nts\n"))
        .collect();
    let file = |path: String, content: String| Op::FileWrite {
        path,
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = match directive(&main, "confdir") {
        Some(dir) if matches!(dir.as_str(), "/etc/chrony.d" | "/etc/chrony/conf.d") => vec![file(
            format!("{dir}/70-ibexwall-nts.conf"),
            format!("# Managed by IbexWall (net.nts).\n{servers}"),
        )],
        Some(dir) => {
            return Err(PluginError::invalid(
                "config",
                format!("confdir `{dir}` is not one IbexWall may write to"),
            ));
        }
        // No confdir: the wrapper adapter (see the module comment).
        None => {
            let exec = wrapper_exec_start(sandbox, unit)?;
            vec![
                file(
                    WRAPPER_CONF.to_string(),
                    format!(
                        "# Managed by IbexWall (net.nts). The distro's own file first.\ninclude {main_path}\n{servers}"
                    ),
                ),
                file(
                    WRAPPER_UNIT_DROP_IN.to_string(),
                    format!("# Managed by IbexWall (net.nts).\n[Service]\nExecStart=\n{exec}\n"),
                ),
            ]
        }
    };
    if sandbox.exists("/run/chrony/chronyd.pid") || sandbox.exists("/run/chronyd.pid") {
        ops.push(Op::SystemdUnit {
            unit: unit.into(),
            action: UnitAction::Restart,
            now: None,
        });
    }
    Ok(ops)
}

/// The distro's own `ExecStart` with `-f <our config>` after the binary, so
/// every other option (and the sysconfig `$OPTIONS`) stays as shipped.
fn wrapper_exec_start(sandbox: &Sandbox, unit: &str) -> Result<String, PluginError> {
    let text = sandbox
        .read(&format!("/usr/lib/systemd/system/{unit}"))
        .or_else(|| sandbox.read(&format!("/etc/systemd/system/{unit}")))
        .ok_or_else(|| PluginError::invalid("config", format!("cannot read {unit}")))?;
    let line = text
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("ExecStart="))
        .ok_or_else(|| PluginError::invalid("config", format!("{unit} has no ExecStart")))?;
    let (binary, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    if !(binary.ends_with("/chronyd") && binary.starts_with('/')) {
        return Err(PluginError::invalid(
            "config",
            format!("{unit} does not start chronyd the expected way"),
        ));
    }
    Ok(
        format!("ExecStart={binary} -f {WRAPPER_CONF} {}", rest.trim())
            .trim_end()
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-nts-{}-{}",
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

    const CHRONYD: (&str, &str) = ("/usr/sbin/chronyd", "");
    const RUNNING: (&str, &str) = ("/run/chrony/chronyd.pid", "1234");
    const FEDORA_CONF: (&str, &str) = (
        "/etc/chrony.conf",
        "pool 2.fedora.pool.ntp.org iburst\nconfdir /etc/chrony.d\n",
    );

    #[test]
    fn without_chrony_there_is_a_finding_and_no_plan() {
        let (root, sandbox) = tree(&[]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(report.results[0].outcome, CheckOutcome::Fail);
        assert_eq!(report.findings[0].id, "nts.missing");
        assert!(report.findings[0].remediation.is_none());
        assert!(plan(&sandbox, &Config::default()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plain_sources_fail_and_any_nts_source_passes_wherever_it_is() {
        let (root, sandbox) = tree(&[CHRONYD, FEDORA_CONF]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
        for (path, content) in [
            (
                "/etc/chrony.d/50-x.conf",
                "server time.cloudflare.com iburst nts\n",
            ),
            ("/etc/chrony.d/50-x.sources", "server ignored.example nts\n"),
        ] {
            let (root, sandbox) = tree(&[CHRONYD, RUNNING, FEDORA_CONF, (path, content)]);
            let expected = if path.ends_with(".conf") {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            };
            assert_eq!(
                evaluate(&sandbox, "now").results[0].outcome,
                expected,
                "{path}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
        // Debian: a sourcedir with .sources files.
        let (root, sandbox) = tree(&[
            CHRONYD,
            RUNNING,
            (
                "/etc/chrony/chrony.conf",
                "confdir /etc/chrony/conf.d\nsourcedir /etc/chrony/sources.d\n",
            ),
            (
                "/etc/chrony/sources.d/x.sources",
                "server nts.netnod.se iburst nts\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_nts_source_without_a_running_chronyd_is_not_a_pass() {
        let (root, sandbox) = tree(&[
            CHRONYD,
            (
                "/etc/chrony.conf",
                "pool 2.fedora.pool.ntp.org iburst\nconfdir /etc/chrony.d\n",
            ),
            (
                "/etc/chrony.d/50-x.conf",
                "server time.cloudflare.com iburst nts\n",
            ),
        ]);
        // Configured for NTS but chronyd is stopped: the clock is not
        // actually authenticated, so this is not a pass.
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::NotAssessed
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn commented_lines_do_not_count() {
        let (root, sandbox) = tree(&[
            CHRONYD,
            (
                "/etc/chrony.conf",
                "# server time.cloudflare.com iburst nts\nconfdir /etc/chrony.d\n",
            ),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_adds_the_presets_servers_in_the_distros_confdir() {
        let (root, sandbox) = tree(&[
            CHRONYD,
            FEDORA_CONF,
            ("/usr/lib/systemd/system/chronyd.service", ""),
            ("/run/chrony/chronyd.pid", "1\n"),
        ]);
        let ops = plan(
            &sandbox,
            &Config {
                preset: Some("cloudflare,ptb".into()),
                servers: Some("Time.Example.org".into()),
            },
        )
        .unwrap();
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, "/etc/chrony.d/70-ibexwall-nts.conf");
        for line in [
            "server time.cloudflare.com iburst nts",
            "server ptbtime1.ptb.de iburst nts",
            "server ptbtime2.ptb.de iburst nts",
            "server time.example.org iburst nts",
        ] {
            assert!(content.contains(line), "{line}");
        }
        assert!(
            matches!(&ops[1], Op::SystemdUnit { unit, action: UnitAction::Restart, .. } if unit == "chronyd.service")
        );
        std::fs::remove_dir_all(root).unwrap();
        // Debian's layout and unit name.
        let (root, sandbox) = tree(&[
            CHRONYD,
            ("/etc/chrony/chrony.conf", "confdir /etc/chrony/conf.d\n"),
            ("/run/chrony/chronyd.pid", "1\n"),
        ]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        assert!(
            matches!(&ops[0], Op::FileWrite { path, .. } if path == "/etc/chrony/conf.d/70-ibexwall-nts.conf")
        );
        assert!(matches!(&ops[1], Op::SystemdUnit { unit, .. } if unit == "chrony.service"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bad_input_and_unreadable_layouts_are_refused_at_plan_time() {
        let (root, sandbox) = tree(&[CHRONYD, FEDORA_CONF]);
        for bad in [
            "-bad.example",
            "a b",
            "evil.example\nserver x",
            "..",
            "x_y.example",
        ] {
            let error = plan(
                &sandbox,
                &Config {
                    servers: Some(bad.into()),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains("not a host name"), "{bad}");
        }
        let error = plan(
            &sandbox,
            &Config {
                preset: Some("mystery".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("choose cloudflare"));
        std::fs::remove_dir_all(root).unwrap();
        // No confdir and a unit that does not start chronyd the expected way.
        let (root, sandbox) = tree(&[
            CHRONYD,
            ("/etc/chrony.conf", "pool x iburst\n"),
            (
                "/usr/lib/systemd/system/chronyd.service",
                "[Service]\nExecStart=/bin/true\n",
            ),
        ]);
        assert!(
            plan(&sandbox, &Config::default())
                .unwrap_err()
                .to_string()
                .contains("expected way")
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[CHRONYD, ("/etc/chrony.conf", "confdir /tmp/evil\n")]);
        assert!(
            plan(&sandbox, &Config::default())
                .unwrap_err()
                .to_string()
                .contains("may write to")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_a_confdir_the_wrapper_adapter_includes_the_distros_file_and_keeps_its_exec_options()
    {
        for (unit_text, expected) in [
            (
                "[Service]\nEnvironmentFile=-/etc/sysconfig/chronyd\nExecStart=/usr/sbin/chronyd $OPTIONS\n",
                "ExecStart=/usr/sbin/chronyd -f /etc/chrony-ibexwall/chrony.conf $OPTIONS",
            ),
            (
                "[Service]\nExecStart=/usr/bin/chronyd -n\n",
                "ExecStart=/usr/bin/chronyd -f /etc/chrony-ibexwall/chrony.conf -n",
            ),
        ] {
            let (root, sandbox) = tree(&[
                CHRONYD,
                (
                    "/etc/chrony.conf",
                    "pool 2.fedora.pool.ntp.org iburst\nsourcedir /run/chrony-dhcp\n",
                ),
                ("/usr/lib/systemd/system/chronyd.service", unit_text),
                ("/run/chrony/chronyd.pid", "1\n"),
            ]);
            let ops = plan(&sandbox, &Config::default()).unwrap();
            let Op::FileWrite { path, content, .. } = &ops[0] else {
                panic!()
            };
            assert_eq!(path, WRAPPER_CONF);
            assert!(content.contains("include /etc/chrony.conf\n"));
            assert!(content.contains("server time.cloudflare.com iburst nts"));
            let Op::FileWrite { path, content, .. } = &ops[1] else {
                panic!()
            };
            assert_eq!(path, WRAPPER_UNIT_DROP_IN);
            // The empty ExecStart resets the distro's, ours replaces it.
            assert!(content.contains("ExecStart=\n"));
            assert!(content.contains(expected), "{content}");
            assert!(matches!(&ops[2], Op::SystemdUnit { unit, .. } if unit == "chronyd.service"));
            // Once in place, the check counts the wrapper's servers.
            let (root2, applied) = tree(&[
                CHRONYD,
                RUNNING,
                ("/etc/chrony.conf", "pool x iburst\n"),
                (
                    WRAPPER_CONF,
                    "include /etc/chrony.conf\nserver time.cloudflare.com iburst nts\n",
                ),
                (WRAPPER_UNIT_DROP_IN, "[Service]\n"),
            ]);
            assert_eq!(
                evaluate(&applied, "now").results[0].outcome,
                CheckOutcome::Pass
            );
            std::fs::remove_dir_all(root2).unwrap();
            std::fs::remove_dir_all(root).unwrap();
        }
        // A wrapper file without the service drop-in is not in effect.
        let (root, sandbox) = tree(&[
            CHRONYD,
            ("/etc/chrony.conf", "pool x iburst\n"),
            (WRAPPER_CONF, "server time.cloudflare.com iburst nts\n"),
        ]);
        assert_eq!(
            evaluate(&sandbox, "now").results[0].outcome,
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stopped_chrony_is_not_started_by_the_plan() {
        let (root, sandbox) = tree(&[CHRONYD, FEDORA_CONF]);
        assert_eq!(plan(&sandbox, &Config::default()).unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
