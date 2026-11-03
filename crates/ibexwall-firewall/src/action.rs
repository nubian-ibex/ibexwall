// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The typed changes IbexWall may ask of firewalld or ufw, and the exact
//! argv each one becomes (ADR-0034). A plugin names an action; it never
//! supplies command-line text.

use serde::{Deserialize, Serialize};

use crate::model::{Backend, Proto};

pub const FIREWALL_CMD: &str = "/usr/bin/firewall-cmd";
pub const UFW: &str = "/usr/sbin/ufw";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FirewallAction {
    AllowPort {
        port: u16,
        proto: Proto,
        #[serde(default)]
        zone: Option<String>,
    },
    RemovePort {
        port: u16,
        proto: Proto,
        #[serde(default)]
        zone: Option<String>,
    },
    AllowService {
        name: String,
        #[serde(default)]
        zone: Option<String>,
    },
    RemoveService {
        name: String,
        #[serde(default)]
        zone: Option<String>,
    },
    /// firewalld only: the zone interfaces without one fall into.
    SetDefaultZone { name: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActionError {
    #[error("port 0 is not a port")]
    PortZero,
    #[error("`{0}` is not a valid name")]
    BadName(String),
    #[error("{backend} cannot do `{what}`")]
    Unsupported {
        backend: &'static str,
        what: &'static str,
    },
}

/// Names (services, zones): letters, digits, `-` and `_`, starting with a
/// letter or digit, at most 48 characters. Nothing that could be read as
/// an option or a path.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.len() <= 48
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl FirewallAction {
    fn zone(&self) -> Option<&str> {
        match self {
            Self::AllowPort { zone, .. }
            | Self::RemovePort { zone, .. }
            | Self::AllowService { zone, .. }
            | Self::RemoveService { zone, .. } => zone.as_deref(),
            Self::SetDefaultZone { .. } => None,
        }
    }

    fn what(&self) -> &'static str {
        match self {
            Self::AllowPort { .. } => "allow_port",
            Self::RemovePort { .. } => "remove_port",
            Self::AllowService { .. } => "allow_service",
            Self::RemoveService { .. } => "remove_service",
            Self::SetDefaultZone { .. } => "set_default_zone",
        }
    }
}

/// Checks an action against what `backend` can do.
pub fn validate(backend: Backend, action: &FirewallAction) -> Result<(), ActionError> {
    match action {
        FirewallAction::AllowPort { port, .. } | FirewallAction::RemovePort { port, .. }
            if *port == 0 =>
        {
            return Err(ActionError::PortZero);
        }
        FirewallAction::AllowService { name, .. }
        | FirewallAction::RemoveService { name, .. }
        | FirewallAction::SetDefaultZone { name }
            if !valid_name(name) =>
        {
            return Err(ActionError::BadName(name.clone()));
        }
        _ => {}
    }
    if let Some(zone) = action.zone()
        && !valid_name(zone)
    {
        return Err(ActionError::BadName(zone.into()));
    }
    match backend {
        Backend::Firewalld => Ok(()),
        Backend::Ufw => {
            // ufw has no zones, and its "services" are application
            // profiles, which IbexWall does not manage.
            if action.zone().is_some()
                || matches!(
                    action,
                    FirewallAction::AllowService { .. }
                        | FirewallAction::RemoveService { .. }
                        | FirewallAction::SetDefaultZone { .. }
                )
            {
                return Err(ActionError::Unsupported {
                    backend: "ufw",
                    what: action.what(),
                });
            }
            Ok(())
        }
        Backend::Nftables => Err(ActionError::Unsupported {
            backend: "nftables",
            what: action.what(),
        }),
    }
}

/// The commands that carry out `action`, in order. The caller validates
/// first; an invalid action yields no commands.
pub fn argv(backend: Backend, action: &FirewallAction) -> Vec<Vec<String>> {
    if validate(backend, action).is_err() {
        return vec![];
    }
    match backend {
        Backend::Firewalld => {
            let change = match action {
                FirewallAction::AllowPort { port, proto, .. } => {
                    format!("--add-port={port}/{}", proto.name())
                }
                FirewallAction::RemovePort { port, proto, .. } => {
                    format!("--remove-port={port}/{}", proto.name())
                }
                FirewallAction::AllowService { name, .. } => format!("--add-service={name}"),
                FirewallAction::RemoveService { name, .. } => format!("--remove-service={name}"),
                // The default zone is permanent by nature: one command, and
                // the daemon applies it at once.
                FirewallAction::SetDefaultZone { name } => {
                    return vec![vec![
                        FIREWALL_CMD.to_string(),
                        format!("--set-default-zone={name}"),
                    ]];
                }
            };
            let command = |permanent: bool| {
                let mut words = vec![FIREWALL_CMD.to_string()];
                if permanent {
                    words.push("--permanent".into());
                }
                if let Some(zone) = action.zone() {
                    words.push(format!("--zone={zone}"));
                }
                words.push(change.clone());
                words
            };
            // Permanent first: if it fails, nothing changed at runtime.
            vec![command(true), command(false)]
        }
        Backend::Ufw => match action {
            FirewallAction::AllowPort { port, proto, .. } => {
                vec![vec![
                    UFW.into(),
                    "allow".into(),
                    format!("{port}/{}", proto.name()),
                ]]
            }
            FirewallAction::RemovePort { port, proto, .. } => vec![vec![
                UFW.into(),
                "delete".into(),
                "allow".into(),
                format!("{port}/{}", proto.name()),
            ]],
            _ => vec![],
        },
        Backend::Nftables => vec![],
    }
}

/// The command that makes the manager re-read its (restored) files.
pub fn reload_argv(backend: Backend) -> Option<Vec<String>> {
    match backend {
        Backend::Firewalld => Some(vec![FIREWALL_CMD.into(), "--reload".into()]),
        Backend::Ufw => Some(vec![UFW.into(), "reload".into()]),
        Backend::Nftables => None,
    }
}

/// The files an action may change, to snapshot before running it.
/// `default_zone` is firewalld's current default.
pub fn snapshot_paths(
    backend: Backend,
    action: &FirewallAction,
    default_zone: &str,
) -> Vec<String> {
    match backend {
        Backend::Firewalld => {
            if matches!(action, FirewallAction::SetDefaultZone { .. }) {
                // The setting lives in firewalld.conf; the zone files stay.
                return vec!["/etc/firewalld/firewalld.conf".into()];
            }
            let zone = action.zone().unwrap_or(default_zone);
            if valid_name(zone) {
                vec![format!("/etc/firewalld/zones/{zone}.xml")]
            } else {
                vec![]
            }
        }
        Backend::Ufw => vec!["/etc/ufw/user.rules".into(), "/etc/ufw/user6.rules".into()],
        Backend::Nftables => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(port: u16, proto: Proto) -> FirewallAction {
        FirewallAction::AllowPort {
            port,
            proto,
            zone: None,
        }
    }

    #[test]
    fn firewalld_changes_permanent_first_then_runtime() {
        let commands = argv(Backend::Firewalld, &allow(8080, Proto::Tcp));
        assert_eq!(
            commands,
            vec![
                vec![FIREWALL_CMD, "--permanent", "--add-port=8080/tcp"],
                vec![FIREWALL_CMD, "--add-port=8080/tcp"],
            ]
        );
        let with_zone = FirewallAction::RemoveService {
            name: "ssh".into(),
            zone: Some("FedoraWorkstation".into()),
        };
        assert_eq!(
            argv(Backend::Firewalld, &with_zone)[0],
            vec![
                FIREWALL_CMD,
                "--permanent",
                "--zone=FedoraWorkstation",
                "--remove-service=ssh"
            ]
        );
    }

    #[test]
    fn ufw_maps_to_allow_and_delete() {
        assert_eq!(
            argv(Backend::Ufw, &allow(53, Proto::Udp)),
            vec![vec![UFW, "allow", "53/udp"]]
        );
        let remove = FirewallAction::RemovePort {
            port: 22,
            proto: Proto::Tcp,
            zone: None,
        };
        assert_eq!(
            argv(Backend::Ufw, &remove),
            vec![vec![UFW, "delete", "allow", "22/tcp"]]
        );
    }

    #[test]
    fn invalid_actions_produce_no_commands() {
        assert_eq!(
            validate(Backend::Firewalld, &allow(0, Proto::Tcp)),
            Err(ActionError::PortZero)
        );
        for name in ["", "-rf", "../x", "a b", "x;y", "a\nb", &"a".repeat(60)] {
            let action = FirewallAction::AllowService {
                name: name.into(),
                zone: None,
            };
            assert!(validate(Backend::Firewalld, &action).is_err(), "{name:?}");
            assert!(argv(Backend::Firewalld, &action).is_empty());
        }
        let bad_zone = FirewallAction::AllowPort {
            port: 1,
            proto: Proto::Tcp,
            zone: Some("--reload".into()),
        };
        assert!(validate(Backend::Firewalld, &bad_zone).is_err());
    }

    #[test]
    fn each_backend_refuses_what_it_cannot_do() {
        let service = FirewallAction::AllowService {
            name: "http".into(),
            zone: None,
        };
        assert!(validate(Backend::Firewalld, &service).is_ok());
        assert!(matches!(
            validate(Backend::Ufw, &service),
            Err(ActionError::Unsupported { backend: "ufw", .. })
        ));
        let zoned = FirewallAction::AllowPort {
            port: 1,
            proto: Proto::Tcp,
            zone: Some("home".into()),
        };
        assert!(validate(Backend::Ufw, &zoned).is_err());
        assert!(validate(Backend::Nftables, &allow(1, Proto::Tcp)).is_err());
        assert!(argv(Backend::Nftables, &allow(1, Proto::Tcp)).is_empty());
    }

    #[test]
    fn reload_and_snapshot_paths_follow_the_backend() {
        assert_eq!(
            reload_argv(Backend::Firewalld),
            Some(vec![FIREWALL_CMD.to_string(), "--reload".to_string()])
        );
        assert_eq!(reload_argv(Backend::Nftables), None);
        assert_eq!(
            snapshot_paths(Backend::Firewalld, &allow(1, Proto::Tcp), "public"),
            vec!["/etc/firewalld/zones/public.xml"]
        );
        let zoned = FirewallAction::AllowPort {
            port: 1,
            proto: Proto::Tcp,
            zone: Some("home".into()),
        };
        assert_eq!(
            snapshot_paths(Backend::Firewalld, &zoned, "public"),
            vec!["/etc/firewalld/zones/home.xml"]
        );
        // A default zone that is not a plain name yields no path.
        assert!(snapshot_paths(Backend::Firewalld, &allow(1, Proto::Tcp), "../x").is_empty());
        assert_eq!(
            snapshot_paths(Backend::Ufw, &allow(1, Proto::Tcp), "").len(),
            2
        );
    }

    #[test]
    fn actions_round_trip_and_reject_unknown_fields() {
        let json = serde_json::json!({"action": "allow_port", "port": 8080, "proto": "tcp"});
        let parsed: FirewallAction = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, allow(8080, Proto::Tcp));
        let extra =
            serde_json::json!({"action": "allow_port", "port": 1, "proto": "tcp", "args": "--x"});
        assert!(serde_json::from_value::<FirewallAction>(extra).is_err());
        let unknown = serde_json::json!({"action": "flush"});
        assert!(serde_json::from_value::<FirewallAction>(unknown).is_err());
    }

    #[test]
    fn the_default_zone_is_one_command_and_snapshots_the_conf_file() {
        let action = FirewallAction::SetDefaultZone {
            name: "home".into(),
        };
        assert_eq!(
            argv(Backend::Firewalld, &action),
            vec![vec![FIREWALL_CMD, "--set-default-zone=home"]]
        );
        assert_eq!(
            snapshot_paths(Backend::Firewalld, &action, "public"),
            vec!["/etc/firewalld/firewalld.conf"]
        );
        assert!(validate(Backend::Ufw, &action).is_err());
        assert!(validate(Backend::Nftables, &action).is_err());
        let bad = FirewallAction::SetDefaultZone {
            name: "--reload".into(),
        };
        assert!(validate(Backend::Firewalld, &bad).is_err());
        assert!(argv(Backend::Firewalld, &bad).is_empty());
    }
}
