// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading what firewalld and ufw already allow, from their own files.
//! Anything unusual is kept as a display line in `other`, never dropped
//! and never edited.

use crate::model::{Backend, PortRule, Proto, State};

/// `DefaultZone=public` from `/etc/firewalld/firewalld.conf`.
pub fn firewalld_default_zone(conf: &str) -> Option<String> {
    conf.lines()
        .filter_map(|line| line.trim().strip_prefix("DefaultZone="))
        .map(|zone| zone.trim().to_string())
        .find(|zone| !zone.is_empty())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Zone {
    pub target: Option<String>,
    pub ports: Vec<PortRule>,
    pub services: Vec<String>,
    pub other: Vec<String>,
}

/// One zone file (`/etc/firewalld/zones/<zone>.xml`).
pub fn firewalld_zone(xml: &str) -> Result<Zone, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let root = doc.root_element();
    if root.tag_name().name() != "zone" {
        return Err("not a zone file".into());
    }
    let mut zone = Zone {
        target: root.attribute("target").map(str::to_string),
        ..Zone::default()
    };
    for node in root.children().filter(|n| n.is_element()) {
        match node.tag_name().name() {
            "service" => {
                if let Some(name) = node.attribute("name") {
                    zone.services.push(name.to_string());
                }
            }
            "port" => {
                let proto = node.attribute("protocol").and_then(Proto::parse);
                let port = node.attribute("port").unwrap_or_default();
                match (proto, port.parse::<u16>()) {
                    (Some(proto), Ok(port)) if port != 0 => {
                        zone.ports.push(PortRule { port, proto })
                    }
                    _ => zone.other.push(format!(
                        "port {}/{}",
                        port,
                        node.attribute("protocol").unwrap_or("?")
                    )),
                }
            }
            // Short, description and the like carry no rule.
            "short" | "description" => {}
            "rule" => zone.other.push(format!(
                "rich rule: {}",
                node.text().unwrap_or_default().trim()
            )),
            other => zone.other.push(other.to_string()),
        }
    }
    zone.ports.sort();
    zone.ports.dedup();
    Ok(zone)
}

/// `ENABLED=yes` from `/etc/ufw/ufw.conf`.
pub fn ufw_enabled(conf: &str) -> Option<bool> {
    conf.lines()
        .filter_map(|line| line.trim().strip_prefix("ENABLED="))
        .map(|value| value.trim().eq_ignore_ascii_case("yes"))
        .next_back()
}

/// ufw writes a `### tuple ###` comment line before each rule it generated:
/// `### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in`. Those lines are
/// the stable description of the rule.
pub fn ufw_rules(user_rules: &str) -> (Vec<PortRule>, Vec<String>) {
    let mut ports = Vec::new();
    let mut other = Vec::new();
    for line in user_rules.lines() {
        let Some(tuple) = line.trim().strip_prefix("### tuple ###") else {
            continue;
        };
        let fields: Vec<&str> = tuple.split_whitespace().collect();
        // action proto dport dst sport src direction [comment...]
        let [action, proto, dport, dst, sport, src, direction, ..] = fields.as_slice() else {
            other.push(tuple.trim().to_string());
            continue;
        };
        let open_to_all = |net: &&str| matches!(*net, "0.0.0.0/0" | "::/0");
        let plain = *action == "allow"
            && *direction == "in"
            && *sport == "any"
            && open_to_all(dst)
            && open_to_all(src);
        match (plain, dport.parse::<u16>()) {
            (true, Ok(port)) if port != 0 => {
                let protos: &[Proto] = match *proto {
                    "tcp" => &[Proto::Tcp],
                    "udp" => &[Proto::Udp],
                    "any" => &[Proto::Tcp, Proto::Udp],
                    _ => &[],
                };
                if protos.is_empty() {
                    other.push(tuple.trim().to_string());
                }
                for proto in protos {
                    ports.push(PortRule {
                        port,
                        proto: *proto,
                    });
                }
            }
            _ => other.push(tuple.trim().to_string()),
        }
    }
    ports.sort();
    ports.dedup();
    other.dedup();
    (ports, other)
}

/// The unified state for firewalld, from its files.
pub fn state_from_firewalld(
    active: Option<bool>,
    firewalld_conf: &str,
    zone_xml: Option<&str>,
) -> State {
    let mut state = State {
        backend: Some(Backend::Firewalld),
        active,
        zone: firewalld_default_zone(firewalld_conf),
        ..State::default()
    };
    if let Some(xml) = zone_xml {
        match firewalld_zone(xml) {
            Ok(zone) => {
                state.ports = zone.ports;
                state.services = zone.services;
                state.other = zone.other;
                if let Some(target) = zone.target {
                    state.other.push(format!("target {target}"));
                }
            }
            Err(error) => state.other.push(format!("unreadable zone file: {error}")),
        }
    }
    state
}

/// The unified state for ufw, from its files (IPv4 and IPv6 rule files).
pub fn state_from_ufw(ufw_conf: &str, user_rules: &str, user6_rules: &str) -> State {
    let (mut ports, mut other) = ufw_rules(user_rules);
    let (ports6, other6) = ufw_rules(user6_rules);
    ports.extend(ports6);
    ports.sort();
    ports.dedup();
    other.extend(other6);
    other.dedup();
    State {
        backend: Some(Backend::Ufw),
        active: ufw_enabled(ufw_conf),
        ports,
        other,
        ..State::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<zone target="%%REJECT%%">
  <short>Public</short>
  <description>For use in public areas.</description>
  <service name="ssh"/>
  <service name="dhcpv6-client"/>
  <port protocol="tcp" port="8080"/>
  <port protocol="udp" port="1000-2000"/>
  <port protocol="tcp" port="8080"/>
  <rule family="ipv4"><source address="10.0.0.0/8"/><accept/></rule>
  <forward/>
</zone>
"#;

    #[test]
    fn reads_the_default_zone() {
        let conf = "# comment\nDefaultZone=FedoraWorkstation\nLockdown=no\n";
        assert_eq!(
            firewalld_default_zone(conf).as_deref(),
            Some("FedoraWorkstation")
        );
        assert_eq!(firewalld_default_zone("DefaultZone=\n"), None);
        assert_eq!(firewalld_default_zone(""), None);
    }

    #[test]
    fn reads_ports_services_and_keeps_what_it_does_not_edit() {
        let zone = firewalld_zone(ZONE).unwrap();
        assert_eq!(zone.target.as_deref(), Some("%%REJECT%%"));
        assert_eq!(zone.services, ["ssh", "dhcpv6-client"]);
        assert_eq!(
            zone.ports,
            [PortRule {
                port: 8080,
                proto: Proto::Tcp
            }]
        );
        assert!(zone.other.contains(&"port 1000-2000/udp".to_string()));
        assert!(zone.other.iter().any(|line| line.starts_with("rich rule")));
        assert!(zone.other.contains(&"forward".to_string()));
    }

    #[test]
    fn refuses_files_that_are_not_zones_or_not_xml() {
        assert!(firewalld_zone("<service/>").is_err());
        assert!(firewalld_zone("not xml <<").is_err());
    }

    #[test]
    fn reads_ufw_rules_from_the_tuple_comments() {
        let rules = "\
*filter
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow any 53 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 8080 0.0.0.0/0 any 192.168.1.0/24 in
### tuple ### deny tcp 23 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 6000:6007 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### END RULES ###
";
        let (ports, other) = ufw_rules(rules);
        assert_eq!(
            ports,
            [
                PortRule {
                    port: 22,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 53,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 53,
                    proto: Proto::Udp
                },
            ]
        );
        assert_eq!(other.len(), 3, "{other:?}");
        assert!(other.iter().any(|line| line.contains("192.168.1.0/24")));
        assert!(other.iter().any(|line| line.starts_with("deny tcp 23")));
        assert!(other.iter().any(|line| line.contains("6000:6007")));
    }

    #[test]
    fn ufw_enabled_follows_the_conf_file() {
        assert_eq!(ufw_enabled("# x\nENABLED=yes\nLOGLEVEL=low\n"), Some(true));
        assert_eq!(ufw_enabled("ENABLED=no\n"), Some(false));
        assert_eq!(ufw_enabled(""), None);
    }

    #[test]
    fn the_unified_states_carry_the_backend() {
        let firewalld = state_from_firewalld(Some(true), "DefaultZone=public\n", Some(ZONE));
        assert_eq!(firewalld.backend, Some(Backend::Firewalld));
        assert_eq!(firewalld.zone.as_deref(), Some("public"));
        assert_eq!(firewalld.services.len(), 2);
        assert!(
            firewalld
                .other
                .iter()
                .any(|line| line == "target %%REJECT%%")
        );
        let broken = state_from_firewalld(None, "DefaultZone=public\n", Some("<<"));
        assert!(broken.other[0].starts_with("unreadable zone file"));

        let v4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n";
        let v6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in\n### tuple ### allow tcp 80 ::/0 any ::/0 in\n";
        let ufw = state_from_ufw("ENABLED=yes\n", v4, v6);
        assert_eq!(ufw.backend, Some(Backend::Ufw));
        assert_eq!(ufw.active, Some(true));
        assert_eq!(
            ufw.ports,
            [
                PortRule {
                    port: 22,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 80,
                    proto: Proto::Tcp
                }
            ]
        );
    }
}
