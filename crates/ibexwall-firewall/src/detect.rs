// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which manager owns the firewall, and its state, read through an
//! abstract file reader so the plugin (sandbox), the core (sandbox root)
//! and tests (fixture trees) all share one implementation.

use crate::model::{Backend, PortRule, Proto, State};
use crate::parse;

pub trait Reader {
    /// Contents, or `None` when missing or unreadable ("cannot tell").
    fn read(&self, path: &str) -> Option<String>;
    fn exists(&self, path: &str) -> bool;
}

const FIREWALLD_ACTIVE: &str = "/run/systemd/units/invocation:firewalld.service";
const FIREWALLD_CONF: &str = "/etc/firewalld/firewalld.conf";
const UFW_CONF: &str = "/etc/ufw/ufw.conf";

/// The manager in charge and whether it is filtering: an active manager
/// first, then an installed but inactive one, then none (IbexWall's own
/// chain). `active` is `None` for "no manager" (the caller asks nftables).
pub fn detect(reader: &dyn Reader) -> (Backend, Option<bool>) {
    if reader.exists(FIREWALLD_ACTIVE) {
        return (Backend::Firewalld, Some(true));
    }
    if reader
        .read(UFW_CONF)
        .and_then(|conf| parse::ufw_enabled(&conf))
        == Some(true)
    {
        return (Backend::Ufw, Some(true));
    }
    if reader.exists(FIREWALLD_CONF) || reader.exists("/usr/lib/firewalld") {
        return (Backend::Firewalld, Some(false));
    }
    if reader.exists(UFW_CONF) {
        return (Backend::Ufw, Some(false));
    }
    (Backend::Nftables, None)
}

/// firewalld's default zone: the configured one, else its built-in
/// default (the file often names none).
pub fn firewalld_zone_name(reader: &dyn Reader) -> String {
    reader
        .read(FIREWALLD_CONF)
        .and_then(|conf| parse::firewalld_default_zone(&conf))
        .unwrap_or_else(|| "public".into())
}

/// The unified state, from the manager's files and the live sockets.
pub fn read_state(reader: &dyn Reader) -> State {
    let (backend, active) = detect(reader);
    let mut state = match backend {
        Backend::Firewalld => {
            let zone = firewalld_zone_name(reader);
            // An edited zone lives in /etc; an untouched one only ships
            // with the package.
            let xml = reader
                .read(&format!("/etc/firewalld/zones/{zone}.xml"))
                .or_else(|| reader.read(&format!("/usr/lib/firewalld/zones/{zone}.xml")));
            let mut state = parse::state_from_firewalld(
                active,
                &format!("DefaultZone={zone}\n"),
                xml.as_deref(),
            );
            state.zone = Some(zone);
            state
        }
        Backend::Ufw => parse::state_from_ufw(
            &reader.read(UFW_CONF).unwrap_or_default(),
            &reader.read("/etc/ufw/user.rules").unwrap_or_default(),
            &reader.read("/etc/ufw/user6.rules").unwrap_or_default(),
        ),
        Backend::Nftables => State {
            backend: Some(Backend::Nftables),
            active,
            ..State::default()
        },
    };
    state.listening = listening_ports(
        &reader.read("/proc/net/tcp").unwrap_or_default(),
        &reader.read("/proc/net/tcp6").unwrap_or_default(),
        &reader.read("/proc/net/udp").unwrap_or_default(),
        &reader.read("/proc/net/udp6").unwrap_or_default(),
    );
    state
}

/// Ports with a socket bound on every address (so reachable from other
/// computers if the firewall lets them in): TCP in LISTEN, UDP bound.
pub fn listening_ports(tcp: &str, tcp6: &str, udp: &str, udp6: &str) -> Vec<PortRule> {
    let mut ports = Vec::new();
    for (text, proto, state, wildcard) in [
        (tcp, Proto::Tcp, "0A", "00000000"),
        (tcp6, Proto::Tcp, "0A", "00000000000000000000000000000000"),
        (udp, Proto::Udp, "07", "00000000"),
        (udp6, Proto::Udp, "07", "00000000000000000000000000000000"),
    ] {
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(local), Some(st)) = (fields.get(1), fields.get(3)) else {
                continue;
            };
            let Some((address, port)) = local.split_once(':') else {
                continue;
            };
            if address != wildcard || *st != state {
                continue;
            }
            if let Ok(port) = u16::from_str_radix(port, 16)
                && port != 0
            {
                ports.push(PortRule { port, proto });
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Tree(BTreeMap<&'static str, &'static str>);

    impl Reader for Tree {
        fn read(&self, path: &str) -> Option<String> {
            self.0.get(path).map(|text| text.to_string())
        }
        fn exists(&self, path: &str) -> bool {
            self.0.contains_key(path)
        }
    }

    fn tree(files: &[(&'static str, &'static str)]) -> Tree {
        Tree(files.iter().copied().collect())
    }

    const ZONE: &str = r#"<zone><service name="ssh"/><port protocol="tcp" port="8080"/></zone>"#;

    #[test]
    fn an_active_firewalld_wins_and_the_zone_defaults_to_public() {
        let t = tree(&[
            (FIREWALLD_ACTIVE, ""),
            ("/etc/firewalld/zones/public.xml", ZONE),
            (UFW_CONF, "ENABLED=yes\n"),
        ]);
        assert_eq!(detect(&t), (Backend::Firewalld, Some(true)));
        let state = read_state(&t);
        assert_eq!(state.zone.as_deref(), Some("public"));
        assert_eq!(state.services, ["ssh"]);
        assert_eq!(
            state.ports,
            [PortRule {
                port: 8080,
                proto: Proto::Tcp
            }]
        );
    }

    #[test]
    fn an_untouched_zone_is_read_from_the_package_copy() {
        let t = tree(&[
            (FIREWALLD_ACTIVE, ""),
            (FIREWALLD_CONF, "DefaultZone=FedoraWorkstation\n"),
            ("/usr/lib/firewalld/zones/FedoraWorkstation.xml", ZONE),
        ]);
        let state = read_state(&t);
        assert_eq!(state.zone.as_deref(), Some("FedoraWorkstation"));
        assert_eq!(state.ports.len(), 1);
    }

    #[test]
    fn ufw_enabled_is_detected_and_read() {
        let t = tree(&[
            (UFW_CONF, "ENABLED=yes\n"),
            (
                "/etc/ufw/user.rules",
                "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n",
            ),
        ]);
        assert_eq!(detect(&t), (Backend::Ufw, Some(true)));
        assert_eq!(
            read_state(&t).ports,
            [PortRule {
                port: 22,
                proto: Proto::Tcp
            }]
        );
    }

    #[test]
    fn an_installed_but_inactive_manager_is_reported_as_such() {
        assert_eq!(
            detect(&tree(&[(FIREWALLD_CONF, "")])),
            (Backend::Firewalld, Some(false))
        );
        assert_eq!(
            detect(&tree(&[(UFW_CONF, "ENABLED=no\n")])),
            (Backend::Ufw, Some(false))
        );
    }

    #[test]
    fn no_manager_means_our_own_chain() {
        let state = read_state(&tree(&[]));
        assert_eq!(state.backend, Some(Backend::Nftables));
        assert_eq!(state.active, None);
    }

    #[test]
    fn only_sockets_bound_to_every_address_count_as_exposed() {
        let header = "  sl  local_address rem_address   st tx_queue\n";
        let tcp = format!(
            "{header}   0: 00000000:0016 00000000:0000 0A 0\n   1: 0100007F:0CEA 00000000:0000 0A 0\n   2: 00000000:01BB 00000000:0000 01 0\n"
        );
        let tcp6 = format!(
            "{header}   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0\n   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 0\n"
        );
        let udp = format!(
            "{header}   0: 00000000:0044 00000000:0000 07 0\n   1: 0100007F:0035 00000000:0000 07 0\n"
        );
        let ports = listening_ports(&tcp, &tcp6, &udp, "");
        assert_eq!(
            ports,
            [
                PortRule {
                    port: 22,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 68,
                    proto: Proto::Udp
                },
            ]
        );
        assert!(listening_ports("", "", "", "").is_empty());
        assert!(listening_ports("garbage\nmore garbage\n", "", "", "").is_empty());
    }
}
