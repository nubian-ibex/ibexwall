// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed-operation validation against the plugin manifest (spec §5.3).
//! The core refuses any operation the manifest did not declare; this is
//! the "plugins propose, the core executes" gate.

use ibexwall_proto::{Manifest, Op, RiskFlag, UnitAction};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum OpError {
    #[error("path `{path}` is not in the plugin's write_paths")]
    PathNotWritable { path: String },
    #[error("unit `{unit}` is not in the plugin's units")]
    UnitNotAllowed { unit: String },
    #[error("action `{action:?}` on `{unit}` is not allowed")]
    ActionNotAllowed { action: UnitAction, unit: String },
    #[error("sysctl key `{key}` is not in the plugin's sysctl_keys")]
    SysctlKeyNotAllowed { key: String },
    #[error("exec `{path}` with args {args:?} does not match the manifest allowlist")]
    ExecNotAllowed { path: String, args: Vec<String> },
    #[error("nft object `{name}` does not use the plugin prefix `{prefix}_`")]
    NftPrefixViolation { name: String, prefix: String },
    #[error("op `{op}` has no executor yet ({detail})")]
    NotImplemented {
        op: &'static str,
        detail: &'static str,
    },
    #[error("system-level executors are disabled while running under IBEXWALL_ROOT")]
    SandboxBlocked,
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Validates every op against the manifest. Returns the aggregated risk
/// flags. Adapter-style ops validate here; their executors land with
/// their phases (`NotImplemented` at execution time).
pub fn validate(ops: &[Op], manifest: &Manifest) -> Result<Vec<RiskFlag>, OpError> {
    for op in ops {
        validate_one(op, manifest)?;
    }
    Ok(risk_flags(ops))
}

fn validate_one(op: &Op, manifest: &Manifest) -> Result<(), OpError> {
    match op {
        Op::FileWrite { path, mode, .. } => {
            if !path_under_any(path, &manifest.privileges.write_paths) {
                return Err(OpError::PathNotWritable { path: path.clone() });
            }
            parse_mode(mode).ok_or_else(|| OpError::Invalid {
                field: "mode",
                reason: format!("`{mode}` is not an octal mode like 0644"),
            })?;
            Ok(())
        }
        Op::FileRemove { path } => {
            if !path_under_any(path, &manifest.privileges.write_paths) {
                return Err(OpError::PathNotWritable { path: path.clone() });
            }
            Ok(())
        }
        Op::SystemdUnit { unit, action, .. } => {
            if !manifest.privileges.units.iter().any(|u| u == unit) {
                return Err(OpError::UnitNotAllowed { unit: unit.clone() });
            }
            if !manifest.privileges.unit_actions.contains(action) {
                return Err(OpError::ActionNotAllowed {
                    action: *action,
                    unit: unit.clone(),
                });
            }
            Ok(())
        }
        Op::SysctlSet { key, .. } => {
            if !manifest.privileges.sysctl_keys.iter().any(|k| k == key) {
                return Err(OpError::SysctlKeyNotAllowed { key: key.clone() });
            }
            Ok(())
        }
        Op::Exec { path, args } => {
            let allowed = manifest
                .privileges
                .exec
                .iter()
                .any(|entry| entry.path == *path && entry.args == *args);
            if !allowed {
                return Err(OpError::ExecNotAllowed {
                    path: path.clone(),
                    args: args.clone(),
                });
            }
            Ok(())
        }
        Op::NftFragment { fragment } => validate_nft(fragment, manifest),
        Op::FirewallAdapter { .. } => Ok(()),
        Op::DnsBackend { .. } => Ok(()),
        Op::FlatpakOverride { app_id, args } => {
            if app_id.is_empty() || args.is_empty() {
                return Err(OpError::Invalid {
                    field: "flatpak.override",
                    reason: "app_id and args required".into(),
                });
            }
            Ok(())
        }
        Op::SnapInterface {
            snap, interface, ..
        } => {
            if snap.is_empty() || interface.is_empty() {
                return Err(OpError::Invalid {
                    field: "snap.interface",
                    reason: "snap and interface required".into(),
                });
            }
            Ok(())
        }
        Op::BrowserPolicy { browser, policy } => {
            // Only a known browser and exactly the DoH-off policy; the
            // path must be under the plugin's declared write paths, like
            // every other file the engine writes.
            let target =
                ibexwall_sys::browser::target(browser).ok_or_else(|| OpError::Invalid {
                    field: "browser.policy",
                    reason: format!("unknown browser `{browser}`"),
                })?;
            if ibexwall_sys::browser::doh_off(browser).as_ref() != Some(policy) {
                return Err(OpError::Invalid {
                    field: "browser.policy",
                    reason: "only the exact disable-DoH policy may be written".into(),
                });
            }
            if !path_under_any(target.path, &manifest.privileges.write_paths) {
                return Err(OpError::PathNotWritable {
                    path: target.path.into(),
                });
            }
            Ok(())
        }
        Op::NmSetting { key, value } => {
            if key.is_empty() || value.is_null() {
                return Err(OpError::Invalid {
                    field: "nm.setting",
                    reason: "key and value required".into(),
                });
            }
            Ok(())
        }
        Op::PackageInstall { package } => {
            if package.is_empty() {
                return Err(OpError::Invalid {
                    field: "package.install",
                    reason: "package required".into(),
                });
            }
            Ok(())
        }
    }
}

/// All nft chains/sets in the fragment must carry the plugin prefix.
fn validate_nft(fragment: &serde_json::Value, manifest: &Manifest) -> Result<(), OpError> {
    let Some(prefix) = manifest.privileges.nft_prefix.clone() else {
        return Err(OpError::Invalid {
            field: "nft.fragment",
            reason: "plugin declares no nft_prefix".into(),
        });
    };
    // Typed fragment only: unknown fields and structural limits are
    // refused before anything is compiled to nftables.
    let fragment = ibexwall_sys::ops::parse_fragment(fragment).map_err(|e| OpError::Invalid {
        field: "nft.fragment",
        reason: e.to_string(),
    })?;
    for name in fragment.chain_names() {
        if !name.starts_with(&format!("{prefix}_")) {
            return Err(OpError::NftPrefixViolation { name, prefix });
        }
    }
    Ok(())
}

fn path_under_any(path: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| path == root || path.starts_with(&format!("{root}/")))
}

fn parse_mode(mode: &str) -> Option<u32> {
    u32::from_str_radix(mode, 8).ok().filter(|m| *m <= 0o7777)
}

/// Risk flags derived from the operations themselves (spec §4.5).
pub fn risk_flags(ops: &[Op]) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    let mut push = |flag| {
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    };
    for op in ops {
        match op {
            Op::FileWrite { path, .. } | Op::FileRemove { path } => {
                if is_network_artifact(path) {
                    push(RiskFlag::Network);
                }
            }
            Op::SysctlSet { key, .. } => {
                if key.starts_with("net.") {
                    push(RiskFlag::Network);
                }
            }
            Op::NftFragment { .. } | Op::FirewallAdapter { .. } | Op::DnsBackend { .. } => {
                push(RiskFlag::Network);
            }
            Op::BrowserPolicy { .. } => {
                // Steering a browser's DNS is a network change.
                push(RiskFlag::Network);
            }
            Op::PackageInstall { .. } => {
                push(RiskFlag::Irreversible);
            }
            Op::SystemdUnit {
                action: UnitAction::Mask,
                ..
            } => {
                push(RiskFlag::Boot);
            }
            _ => {}
        }
    }
    flags
}

fn is_network_artifact(path: &str) -> bool {
    const NETWORK_PREFIXES: &[&str] = &[
        "/etc/NetworkManager/",
        "/etc/systemd/resolved.conf.d/",
        "/etc/sysconfig/network-scripts/",
        "/etc/netplan/",
        "/etc/wireguard/",
        "/etc/firefox/policies/",
        "/etc/opt/chrome/policies/",
        "/etc/opt/edge/policies/",
        "/etc/chromium/policies/",
        "/etc/chromium-browser/policies/",
        "/etc/brave/policies/",
    ];
    NETWORK_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibexwall_proto::UnitAction;

    fn manifest() -> Manifest {
        let manifest: Manifest = toml::from_str(
            r#"
id = "dev.echo"
version = "1.0.0"
api = 1
category = "dev"
kinds = ["check", "control"]
origin = "local"
license = "GPL-3.0-or-later"
binary = "ibexwall-plugin-echo"
default_enabled = true

[name]
en = "Echo"

[privileges]
write_paths = ["/etc/sysctl.d", "/etc/ibexwall-tests", "/etc/firefox/policies"]
units = ["chronyd.service", "ibexwall-test.service"]
unit_actions = ["start", "stop", "restart"]
sysctl_keys = ["kernel.ibexwall_test", "net.ibexwall_test"]
exec = [{ path = "/usr/bin/sleep", args = ["10"] }]
nft_prefix = "dev_echo"

[sandbox]
user = "dynamic"

[risk]
reversible = "immediate"
"#,
        )
        .unwrap();
        manifest.validate().unwrap();
        manifest
    }

    #[test]
    fn allows_declared_paths_and_refuses_others() {
        let manifest = manifest();
        let ok = &[Op::FileWrite {
            path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
            content: "x".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }];
        assert!(validate(ok, &manifest).is_ok());

        let refused = &[Op::FileWrite {
            path: "/etc/passwd".into(),
            content: "x".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }];
        assert_eq!(
            validate(refused, &manifest),
            Err(OpError::PathNotWritable {
                path: "/etc/passwd".into()
            })
        );
    }

    #[test]
    fn refuses_out_of_manifest_units_actions_and_sysctls() {
        let manifest = manifest();
        assert_eq!(
            validate(
                &[Op::SystemdUnit {
                    unit: "sshd.service".into(),
                    action: UnitAction::Restart,
                    now: None
                }],
                &manifest
            ),
            Err(OpError::UnitNotAllowed {
                unit: "sshd.service".into()
            })
        );
        assert_eq!(
            validate(
                &[Op::SystemdUnit {
                    unit: "chronyd.service".into(),
                    action: UnitAction::Mask,
                    now: None
                }],
                &manifest
            ),
            Err(OpError::ActionNotAllowed {
                action: UnitAction::Mask,
                unit: "chronyd.service".into()
            })
        );
        assert_eq!(
            validate(
                &[Op::SysctlSet {
                    key: "kernel.dmesg_restrict".into(),
                    value: "1".into()
                }],
                &manifest
            ),
            Err(OpError::SysctlKeyNotAllowed {
                key: "kernel.dmesg_restrict".into()
            })
        );
    }

    #[test]
    fn exec_must_match_the_allowlist_exactly() {
        let manifest = manifest();
        let ok = &[Op::Exec {
            path: "/usr/bin/sleep".into(),
            args: vec!["10".into()],
        }];
        assert!(validate(ok, &manifest).is_ok());
        let other_args = &[Op::Exec {
            path: "/usr/bin/sleep".into(),
            args: vec!["9999".into()],
        }];
        assert!(validate(other_args, &manifest).is_err());
        let other_bin = &[Op::Exec {
            path: "/bin/rm".into(),
            args: vec!["-rf".into(), "/".into()],
        }];
        assert!(validate(other_bin, &manifest).is_err());
    }

    fn nft_chain(name: &str) -> serde_json::Value {
        serde_json::json!({ "chains": [{
            "name": name,
            "rules": [{ "oif_loopback": true, "verdict": "accept" }],
        }] })
    }

    #[test]
    fn nft_objects_need_the_plugin_prefix() {
        let manifest = manifest();
        let ok = &[Op::NftFragment {
            fragment: nft_chain("dev_echo_guard"),
        }];
        assert!(validate(ok, &manifest).is_ok());
        let refused = &[Op::NftFragment {
            fragment: nft_chain("firewalld_input"),
        }];
        assert_eq!(
            validate(refused, &manifest),
            Err(OpError::NftPrefixViolation {
                name: "firewalld_input".into(),
                prefix: "dev_echo".into()
            })
        );
    }

    #[test]
    fn browser_policy_paths_carry_the_network_risk() {
        for browser in ["firefox", "chrome", "chromium", "brave", "edge"] {
            let ops = [Op::BrowserPolicy {
                browser: browser.into(),
                policy: ibexwall_sys::browser::doh_off(browser).unwrap(),
            }];
            assert_eq!(risk_flags(&ops), vec![RiskFlag::Network], "{browser}");
        }
    }

    #[test]
    fn browser_policy_is_strictly_the_known_doh_off_content() {
        let mut manifest = manifest();
        manifest.privileges.write_paths = vec!["/etc/firefox/policies".into()];
        let ok = Op::BrowserPolicy {
            browser: "firefox".into(),
            policy: ibexwall_sys::browser::doh_off("firefox").unwrap(),
        };
        assert!(validate(std::slice::from_ref(&ok), &manifest).is_ok());
        for bad in [
            Op::BrowserPolicy {
                browser: "netscape".into(),
                policy: ibexwall_sys::browser::doh_off("firefox").unwrap(),
            },
            Op::BrowserPolicy {
                browser: "firefox".into(),
                policy: serde_json::json!({ "policies": { "BlockAboutConfig": true } }),
            },
            Op::BrowserPolicy {
                // Known browser, but its path is not in this manifest.
                browser: "chrome".into(),
                policy: ibexwall_sys::browser::doh_off("chrome").unwrap(),
            },
        ] {
            assert!(
                validate(std::slice::from_ref(&bad), &manifest).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn risk_flags_follow_artifacts() {
        let ops = [
            Op::FileWrite {
                path: "/etc/NetworkManager/conf.d/50-ibexwall-dns.conf".into(),
                content: String::new(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SysctlSet {
                key: "net.ipv4.ip_forward".into(),
                value: "0".into(),
            },
            Op::PackageInstall {
                package: "chrony".into(),
            },
        ];
        assert_eq!(
            risk_flags(&ops),
            vec![RiskFlag::Network, RiskFlag::Irreversible]
        );
    }

    #[test]
    fn remove_and_mode_validation() {
        let manifest = manifest();
        assert!(
            validate(
                &[Op::FileRemove {
                    path: "/etc/sysctl.d/x.conf".into()
                }],
                &manifest
            )
            .is_ok()
        );
        assert_eq!(
            validate(
                &[Op::FileRemove {
                    path: "/etc/shadow".into()
                }],
                &manifest
            ),
            Err(OpError::PathNotWritable {
                path: "/etc/shadow".into()
            })
        );
        for bad in ["rwx", "99999", "0888"] {
            let op = Op::FileWrite {
                path: "/etc/sysctl.d/a.conf".into(),
                content: String::new(),
                mode: bad.into(),
                owner: "root".into(),
                group: "root".into(),
            };
            assert!(
                matches!(
                    validate(&[op], &manifest),
                    Err(OpError::Invalid { field: "mode", .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn path_prefix_must_match_a_whole_component() {
        let manifest = manifest();
        // `/etc/sysctl.d-evil` must not be treated as inside `/etc/sysctl.d`.
        let op = Op::FileRemove {
            path: "/etc/sysctl.d-evil/x".into(),
        };
        assert!(validate(&[op], &manifest).is_err());
    }

    #[test]
    fn nft_requires_a_declared_prefix_and_only_accepts_typed_fragments() {
        let mut manifest = manifest();
        let ok = Op::NftFragment {
            fragment: nft_chain("dev_echo_a"),
        };
        assert!(validate(std::slice::from_ref(&ok), &manifest).is_ok());
        // The old free-form shape and unknown fields are refused.
        for untyped in [
            serde_json::json!({ "chain": "dev_echo_a" }),
            serde_json::json!({ "chains": [{ "name": "dev_echo_a", "rules": [], "raw": "x" }] }),
            serde_json::json!({}),
        ] {
            let result = validate(&[Op::NftFragment { fragment: untyped }], &manifest);
            assert!(
                matches!(
                    result,
                    Err(OpError::Invalid {
                        field: "nft.fragment",
                        ..
                    })
                ),
                "{result:?}"
            );
        }
        manifest.privileges.nft_prefix = None;
        assert!(matches!(
            validate(&[ok], &manifest),
            Err(OpError::Invalid {
                field: "nft.fragment",
                ..
            })
        ));
    }

    #[test]
    fn adapter_ops_validate_their_required_fields() {
        let manifest = manifest();
        let good = [
            Op::FirewallAdapter {
                backend: "ufw".into(),
                action: serde_json::json!({}),
            },
            Op::DnsBackend {
                backend: "resolved".into(),
                action: serde_json::json!({}),
            },
            Op::FlatpakOverride {
                app_id: "a.b".into(),
                args: vec!["--unshare=network".into()],
            },
            Op::SnapInterface {
                snap: "s".into(),
                interface: "i".into(),
                connect: true,
            },
            Op::BrowserPolicy {
                browser: "firefox".into(),
                policy: ibexwall_sys::browser::doh_off("firefox").unwrap(),
            },
            Op::NmSetting {
                key: "k".into(),
                value: serde_json::json!("v"),
            },
            Op::PackageInstall {
                package: "chrony".into(),
            },
        ];
        assert!(validate(&good, &manifest).is_ok());
        let bad = [
            Op::FlatpakOverride {
                app_id: String::new(),
                args: vec![],
            },
            Op::SnapInterface {
                snap: String::new(),
                interface: "i".into(),
                connect: true,
            },
            Op::BrowserPolicy {
                browser: "f".into(),
                policy: serde_json::json!({}),
            },
            Op::BrowserPolicy {
                browser: "f".into(),
                policy: serde_json::json!([1]),
            },
            Op::NmSetting {
                key: String::new(),
                value: serde_json::json!(1),
            },
            Op::NmSetting {
                key: "k".into(),
                value: serde_json::Value::Null,
            },
            Op::PackageInstall {
                package: String::new(),
            },
        ];
        for op in bad {
            assert!(
                validate(std::slice::from_ref(&op), &manifest).is_err(),
                "{op:?}"
            );
        }
    }

    #[test]
    fn masking_a_unit_is_a_boot_risk() {
        let ops = [Op::SystemdUnit {
            unit: "u".into(),
            action: UnitAction::Mask,
            now: None,
        }];
        assert_eq!(risk_flags(&ops), vec![RiskFlag::Boot]);
    }

    #[test]
    fn network_artifacts_and_net_sysctls_are_network_risk() {
        for path in [
            "/etc/NetworkManager/conf.d/x",
            "/etc/systemd/resolved.conf.d/x",
            "/etc/netplan/x",
            "/etc/wireguard/x",
            "/etc/sysconfig/network-scripts/x",
        ] {
            let ops = [Op::FileRemove { path: path.into() }];
            assert_eq!(risk_flags(&ops), vec![RiskFlag::Network], "{path}");
        }
        let nonnet = [Op::FileRemove {
            path: "/etc/sysctl.d/x".into(),
        }];
        assert!(risk_flags(&nonnet).is_empty());
        let adapters = [
            Op::FirewallAdapter {
                backend: "x".into(),
                action: serde_json::json!({}),
            },
            Op::NftFragment {
                fragment: serde_json::json!({}),
            },
        ];
        assert_eq!(risk_flags(&adapters), vec![RiskFlag::Network]);
    }
}
