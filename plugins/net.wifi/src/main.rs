// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.wifi`: two things NetworkManager decides about Wi-Fi privacy.
//! Whether the card's real hardware address is shown to every network
//! (`wifi.cloned-mac-address`, default `preserve`), and whether open
//! networks are remembered and rejoined by themselves. The check reads
//! NetworkManager's configuration the way it does (later files win, `/etc`
//! over `/usr/lib`) and the saved connection files; the control writes one
//! owned drop-in setting the address policy and restarts NetworkManager
//! (which keeps existing connections). Network names are untrusted text and
//! travel as arguments only.

use std::collections::BTreeMap;

use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Remediation, Severity,
    UnitAction,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

const DROP_IN: &str = "/etc/NetworkManager/conf.d/70-ibexwall-wifi.conf";

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Wifi)) {
        eprintln!("ibexwall-plugin-wifi: {err}");
        std::process::exit(1);
    }
}

struct Wifi;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// `stable` (a fixed fake address per network, the default: sign-in
    /// pages and DHCP leases keep working) or `random` (a new one at every
    /// connection).
    pub mode: Option<String>,
}

impl Plugin for Wifi {
    fn id(&self) -> &'static str {
        "net.wifi"
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

fn nm_installed(sandbox: &Sandbox) -> bool {
    sandbox.exists("/usr/sbin/NetworkManager") || sandbox.exists("/usr/bin/NetworkManager")
}

/// `key` of `[section]` after reading NetworkManager's files in its order:
/// `/usr/lib` below `/etc`, the main file, then `conf.d` by name.
fn config_value(sandbox: &Sandbox, section: &str, key: &str) -> Option<String> {
    let mut files: Vec<String> = Vec::new();
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for base in ["/usr/lib/NetworkManager", "/etc/NetworkManager"] {
        for name in sandbox.list(&format!("{base}/conf.d")) {
            if name.ends_with(".conf") {
                by_name.insert(name.clone(), format!("{base}/conf.d/{name}"));
            }
        }
    }
    files.push("/etc/NetworkManager/NetworkManager.conf".into());
    files.extend(by_name.into_values());
    let mut found = None;
    for file in files {
        let Some(text) = sandbox.read(&file) else {
            continue;
        };
        let mut inside = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                // NetworkManager takes any `[connection*]` section as connection
                // defaults (Fedora uses `[connection-wifi-...]`), not one name.
                inside =
                    name == section || (section == "connection" && name.starts_with("connection"));
            } else if inside
                && let Some((k, v)) = line.split_once('=')
                && k.trim() == key
            {
                found = Some(v.trim().to_string());
            }
        }
    }
    found
}

/// Saved Wi-Fi connections with no security: `(name)`.
fn open_networks(sandbox: &Sandbox) -> Vec<String> {
    let dir = "/etc/NetworkManager/system-connections";
    let mut open = Vec::new();
    for file in sandbox.list(dir) {
        let Some(text) = sandbox.read(&format!("{dir}/{file}")) else {
            continue;
        };
        let mut section = String::new();
        let (mut wifi, mut secured, mut name) = (false, false, String::new());
        for line in text.lines().map(str::trim) {
            if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = s.to_string();
            } else if let Some((k, v)) = line.split_once('=') {
                match (section.as_str(), k.trim()) {
                    ("connection", "type") => {
                        wifi = v.trim() == "wifi" || v.trim() == "802-11-wireless"
                    }
                    ("wifi", "ssid") | ("802-11-wireless", "ssid") => name = v.trim().to_string(),
                    ("connection", "id") if name.is_empty() => name = v.trim().to_string(),
                    ("wifi-security", "key-mgmt") | ("802-11-wireless-security", "key-mgmt") => {
                        secured = !v.trim().is_empty()
                    }
                    _ => {}
                }
            }
        }
        if wifi && !secured {
            open.push(name);
        }
    }
    open
}

pub fn evaluate(sandbox: &Sandbox, detected_at: &str) -> CheckReport {
    let mut findings = Vec::new();
    let mut results = Vec::new();
    if !nm_installed(sandbox) {
        for id in ["wifi.mac_randomization", "wifi.open_networks"] {
            results.push(CheckResult {
                id: id.into(),
                severity: Severity::Low,
                outcome: CheckOutcome::NotApplicable,
            });
        }
        return CheckReport { results, findings };
    }
    let finding = |kind: &str, severity, args: BTreeMap<String, String>, remediation| Finding {
        id: match args.get("name") {
            Some(name) => format!("wifi.{kind}.{name}"),
            None => format!("wifi.{kind}"),
        },
        plugin: "net.wifi".into(),
        severity,
        title_key: format!("wifi-{kind}-title"),
        summary_key: format!("wifi-{kind}-summary"),
        args,
        references: vec![],
        remediation,
        status: FindingStatus::Open,
        detected_at: detected_at.into(),
    };

    let value = config_value(sandbox, "connection", "wifi.cloned-mac-address")
        .unwrap_or_else(|| "preserve".into());
    let protected = matches!(value.as_str(), "random" | "stable" | "stable-ssid");
    if !protected {
        let mut args = BTreeMap::new();
        args.insert("value".to_string(), value);
        findings.push(finding(
            "mac",
            Severity::Low,
            args,
            Some(Remediation {
                plan_template: Some("wifi.mac".into()),
                may_affect_keys: vec![
                    "wifi-may-affect-captive".into(),
                    "wifi-may-affect-filters".into(),
                ],
            }),
        ));
    }
    results.push(CheckResult {
        id: "wifi.mac_randomization".into(),
        severity: Severity::Low,
        outcome: if protected {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        },
    });

    // The saved connections are root-only: unreadable means not assessed.
    let outcome = if sandbox.is_unreadable_dir("/etc/NetworkManager/system-connections") {
        CheckOutcome::NotAssessed
    } else {
        let open = open_networks(sandbox);
        for name in &open {
            let mut args = BTreeMap::new();
            args.insert("name".to_string(), name.clone());
            findings.push(finding("open", Severity::Medium, args, None));
        }
        if open.is_empty() {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        }
    };
    results.push(CheckResult {
        id: "wifi.open_networks".into(),
        severity: Severity::Medium,
        outcome,
    });
    CheckReport { results, findings }
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    if !nm_installed(sandbox) {
        return Err(PluginError::invalid(
            "config",
            "NetworkManager is not installed".to_string(),
        ));
    }
    let mode = config.mode.as_deref().unwrap_or("stable");
    if !matches!(mode, "stable" | "random") {
        return Err(PluginError::invalid(
            "mode",
            format!("`{mode}`: choose stable or random"),
        ));
    }
    let mut ops = vec![Op::FileWrite {
        path: DROP_IN.into(),
        content: format!(
            "# Managed by IbexWall (net.wifi).\n[connection-mac-randomization]\nwifi.cloned-mac-address={mode}\n"
        ),
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }];
    // Only a running NetworkManager is restarted (it keeps the existing
    // connections); a stopped one reads the file when it starts.
    if sandbox.exists("/run/NetworkManager/NetworkManager.pid") {
        ops.push(Op::SystemdUnit {
            unit: "NetworkManager.service".into(),
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
            "ibx-wifi-{}-{}",
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

    const NM: (&str, &str) = ("/usr/sbin/NetworkManager", "");
    const OPEN_CONN: &str =
        "[connection]\nid=Cafe\ntype=wifi\n[wifi]\nssid=Cafe Free WiFi\nmode=infrastructure\n";
    const WPA_CONN: &str = "[connection]\nid=Home\ntype=wifi\n[wifi]\nssid=Home\n[wifi-security]\nkey-mgmt=wpa-psk\npsk=secret\n";

    fn outcome(report: &CheckReport, id: &str) -> CheckOutcome {
        report.results.iter().find(|r| r.id == id).unwrap().outcome
    }

    #[test]
    fn without_networkmanager_nothing_applies() {
        let (root, sandbox) = tree(&[]);
        let report = evaluate(&sandbox, "now");
        assert!(
            report
                .results
                .iter()
                .all(|r| r.outcome == CheckOutcome::NotApplicable)
        );
        assert!(plan(&sandbox, &Config::default()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_default_keeps_the_real_address_and_a_later_file_can_change_it() {
        let (root, sandbox) = tree(&[NM]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(
            outcome(&report, "wifi.mac_randomization"),
            CheckOutcome::Fail
        );
        assert_eq!(report.findings[0].args["value"], "preserve");
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[
            NM,
            (
                "/usr/lib/NetworkManager/conf.d/20-distro.conf",
                "[connection-mac-randomization]\nwifi.cloned-mac-address=preserve\n",
            ),
            (
                "/etc/NetworkManager/conf.d/70-ibexwall-wifi.conf",
                "[connection-mac-randomization]\nwifi.cloned-mac-address=stable\n",
            ),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "wifi.mac_randomization"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn any_connection_section_sets_the_default_as_networkmanager_reads_it() {
        // Fedora ships `[connection-wifi-wifi-mac]`-style sections.
        let (root, sandbox) = tree(&[
            NM,
            (
                "/usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf",
                "[connection-wifi-mac]\nwifi.cloned-mac-address=stable-ssid\n",
            ),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "wifi.mac_randomization"),
            CheckOutcome::Pass
        );
        std::fs::remove_dir_all(root).unwrap();
        // A section that only looks similar does not count.
        let (root, sandbox) = tree(&[
            NM,
            (
                "/etc/NetworkManager/conf.d/x.conf",
                "[device-mac-randomization]\nwifi.cloned-mac-address=random\n",
            ),
        ]);
        assert_eq!(
            outcome(&evaluate(&sandbox, "now"), "wifi.mac_randomization"),
            CheckOutcome::Fail
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn open_saved_networks_are_found_by_name_and_secured_ones_are_not() {
        let (root, sandbox) = tree(&[
            NM,
            (
                "/etc/NetworkManager/system-connections/cafe.nmconnection",
                OPEN_CONN,
            ),
            (
                "/etc/NetworkManager/system-connections/home.nmconnection",
                WPA_CONN,
            ),
            (
                "/etc/NetworkManager/system-connections/vpn.nmconnection",
                "[connection]\nid=work\ntype=vpn\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        assert_eq!(outcome(&report, "wifi.open_networks"), CheckOutcome::Fail);
        let open: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.id.starts_with("wifi.open"))
            .map(|f| f.args["name"].as_str())
            .collect();
        assert_eq!(open, ["Cafe Free WiFi"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_hostile_network_name_stays_an_argument() {
        let (root, sandbox) = tree(&[
            NM,
            (
                "/etc/NetworkManager/system-connections/x.nmconnection",
                "[connection]\ntype=wifi\n[wifi]\nssid=<img src=x onerror=alert(1)>\n",
            ),
        ]);
        let report = evaluate(&sandbox, "now");
        let f = report
            .findings
            .iter()
            .find(|f| f.id.starts_with("wifi.open"))
            .unwrap();
        assert_eq!(f.args["name"], "<img src=x onerror=alert(1)>");
        assert_eq!(f.summary_key, "wifi-open-summary");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_plan_is_one_owned_drop_in_and_a_restart_of_a_running_manager() {
        let (root, sandbox) = tree(&[NM, ("/run/NetworkManager/NetworkManager.pid", "1\n")]);
        let ops = plan(&sandbox, &Config::default()).unwrap();
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, DROP_IN);
        assert!(content.contains("wifi.cloned-mac-address=stable"));
        assert!(
            matches!(&ops[1], Op::SystemdUnit { unit, action: UnitAction::Restart, .. } if unit == "NetworkManager.service")
        );
        let ops = plan(
            &sandbox,
            &Config {
                mode: Some("random".into()),
            },
        )
        .unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        assert!(content.contains("=random"));
        assert!(
            plan(
                &sandbox,
                &Config {
                    mode: Some("preserve".into())
                }
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[NM]);
        assert_eq!(
            plan(&sandbox, &Config::default()).unwrap().len(),
            1,
            "not started by a plan"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
