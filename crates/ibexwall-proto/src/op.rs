// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Typed operations (the only things the core may execute on behalf of a
//! plugin). Plugins propose lists of [`Op`]; the core validates each one
//! against the plugin manifest before snapshot and execution.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Risk flags attached to plans and transactions (spec §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    Network,
    Auth,
    Boot,
    RebootToRevert,
    Irreversible,
}

/// How easily an operation reverses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reversible {
    Immediate,
    Reboot,
    Irreversible,
}

/// Allowed systemd unit actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnitAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    Mask,
    Unmask,
}

/// The typed operation set (spec §5.3).
///
/// Variants serialize with dotted `op` tags (`file.write`, `systemd.unit`,
/// ...). Inverses and validation are the core's job, driven by the plugin
/// manifest's `[privileges]` section.
///
/// Note: serde cannot enforce `deny_unknown_fields` on internally tagged
/// enums; the core re-validates every deserialized op strictly (F1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op")]
pub enum Op {
    /// Write a file inside declared `write_paths`; atomic write, no symlink
    /// following, declared mode/owner.
    #[serde(rename = "file.write")]
    FileWrite {
        path: String,
        content: String,
        mode: String,
        owner: String,
        group: String,
    },
    /// Remove a file that IbexWall itself created inside `write_paths`.
    #[serde(rename = "file.remove")]
    FileRemove { path: String },
    /// Start/stop/enable/disable/mask a unit listed in `units`.
    #[serde(rename = "systemd.unit")]
    SystemdUnit {
        unit: String,
        action: UnitAction,
        #[serde(default)]
        now: Option<bool>,
    },
    /// Set a sysctl key listed in `sysctl_keys`, persisted in a drop-in.
    #[serde(rename = "sysctl.set")]
    SysctlSet { key: String, value: String },
    /// Contribute a fragment (chains/sets with the plugin's prefix) to
    /// `table inet ibexwall`; the core recomposes the table atomically.
    #[serde(rename = "nft.fragment")]
    NftFragment { fragment: Value },
    /// Drive the detected firewall backend (firewalld/ufw/bare nftables).
    #[serde(rename = "firewall.adapter")]
    FirewallAdapter { backend: String, action: Value },
    /// Drive the detected DNS backend (resolved/NM/resolv.conf drop-ins).
    #[serde(rename = "dns.backend")]
    DnsBackend { backend: String, action: Value },
    /// Apply Flatpak overrides (e.g. `--unshare=network`).
    #[serde(rename = "flatpak.override")]
    FlatpakOverride { app_id: String, args: Vec<String> },
    /// Connect/disconnect a Snap interface.
    #[serde(rename = "snap.interface")]
    SnapInterface {
        snap: String,
        interface: String,
        connect: bool,
    },
    /// Write an allowed browser policy key (with user consent).
    #[serde(rename = "browser.policy")]
    BrowserPolicy { browser: String, policy: Value },
    /// Set an allowed NetworkManager key (MAC randomization, global DNS).
    #[serde(rename = "nm.setting")]
    NmSetting { key: String, value: Value },
    /// Install a package via PackageKit only; never automatically
    /// reversible (flagged in the plan).
    #[serde(rename = "package.install")]
    PackageInstall { package: String },
    /// Make a self-signed certificate and its private key at the given
    /// paths (inside `write_paths`). The key is made when the plan is
    /// applied and never appears in the plan, so no preview, log or proposal
    /// can hold it. Rollback removes both files, or restores the old ones.
    #[serde(rename = "tls.keypair")]
    TlsKeyPair {
        cert_path: String,
        key_path: String,
        /// Names or addresses clients will use.
        hosts: Vec<String>,
        days: u32,
        /// Group that may read the key (mode 0640): `root` or one of
        /// IbexWall's own groups.
        key_group: String,
    },
    /// Run an allowlisted binary with fixed argv; no shell.
    #[serde(rename = "exec")]
    Exec { path: String, args: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(op: Op) {
        let value = serde_json::to_value(&op).expect("serialize");
        let back: Op = serde_json::from_value(value.clone()).expect("deserialize");
        assert_eq!(op, back);
        assert!(value["op"].is_string());
    }

    #[test]
    fn ops_use_dotted_tags() {
        let value = serde_json::to_value(Op::FileRemove {
            path: "/etc/sysctl.d/90-ibexwall.conf".into(),
        })
        .unwrap();
        assert_eq!(value["op"], "file.remove");
        let value = serde_json::to_value(Op::Exec {
            path: "/usr/bin/chronyc".into(),
            args: vec!["-N".into(), "authdata".into()],
        })
        .unwrap();
        assert_eq!(value["op"], "exec");
    }

    #[test]
    fn ops_roundtrip() {
        roundtrip(Op::FileWrite {
            path: "/etc/chrony.d/ibexwall.conf".into(),
            content: "server time.cloudflare.com iburst nts\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        });
        roundtrip(Op::SystemdUnit {
            unit: "chronyd.service".into(),
            action: UnitAction::Restart,
            now: Some(true),
        });
        roundtrip(Op::SysctlSet {
            key: "kernel.kptr_restrict".into(),
            value: "2".into(),
        });
        roundtrip(Op::NftFragment {
            fragment: serde_json::json!({ "chain": "net_dns_guard" }),
        });
        roundtrip(Op::FlatpakOverride {
            app_id: "org.gnome.Epiphany".into(),
            args: vec!["--unshare=network".into()],
        });
        roundtrip(Op::SnapInterface {
            snap: "firefox".into(),
            interface: "network".into(),
            connect: false,
        });
    }

    #[test]
    fn unknown_op_tag_is_rejected() {
        let err = serde_json::from_value::<Op>(serde_json::json!({ "op": "rm.rf", "path": "/" }));
        assert!(err.is_err());
    }
}
