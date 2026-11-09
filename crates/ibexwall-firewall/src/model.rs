// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

/// Who owns the inbound firewall on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Firewalld,
    Ufw,
    /// Neither: IbexWall's own chain in `table inet ibexwall`.
    Nftables,
}

impl Backend {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "firewalld" => Some(Backend::Firewalld),
            "ufw" => Some(Backend::Ufw),
            "nftables" => Some(Backend::Nftables),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Backend::Firewalld => "firewalld",
            Backend::Ufw => "ufw",
            Backend::Nftables => "nftables",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        }
    }
}

/// One allowed inbound port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    pub proto: Proto,
}

/// What the manager allows today, as far as IbexWall can read it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct State {
    /// `None`: no manager found.
    pub backend: Option<Backend>,
    /// Whether the manager is filtering. `None` when it cannot be told.
    pub active: Option<bool>,
    /// firewalld's default zone.
    pub zone: Option<String>,
    pub ports: Vec<PortRule>,
    pub services: Vec<String>,
    /// Ports with a socket bound on every address (reachable from other
    /// computers when the firewall allows them).
    pub listening: Vec<PortRule>,
    /// Rules we read but do not edit (ranges, rich rules, other targets),
    /// shown as the manager wrote them.
    pub other: Vec<String>,
}

impl State {
    /// Whether `rule` is let in: listed on its own, or inside a range the
    /// manager allows (Fedora Workstation's zone allows 1025-65535, for
    /// one, and firewalld then refuses to add a port inside it).
    pub fn allows(&self, rule: PortRule) -> bool {
        self.ports.contains(&rule) || self.covering_range(rule).is_some()
    }

    /// The range rule, as shown, that lets `rule` in.
    pub fn covering_range(&self, rule: PortRule) -> Option<&str> {
        self.other
            .iter()
            .find(|text| range_covers(text, rule))
            .map(String::as_str)
    }
}

fn in_range(range: &str, separator: char, port: u16) -> bool {
    let Some((low, high)) = range.split_once(separator) else {
        return false;
    };
    match (low.parse::<u16>(), high.parse::<u16>()) {
        (Ok(low), Ok(high)) => (low..=high).contains(&port),
        _ => false,
    }
}

fn proto_covers(text: &str, proto: Proto) -> bool {
    text == proto.name() || text == "any"
}

/// A firewalld `port a-b/proto` or a plain ufw `allow` tuple whose port is
/// a range `a:b`, open to every address, inbound.
fn range_covers(text: &str, rule: PortRule) -> bool {
    if let Some(rest) = text.strip_prefix("port ") {
        return rest.split_once('/').is_some_and(|(range, proto)| {
            proto_covers(proto, rule.proto) && in_range(range, '-', rule.port)
        });
    }
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [action, proto, dport, dst, sport, src, direction, ..] = fields.as_slice() else {
        return false;
    };
    let open = |net: &&str| matches!(*net, "0.0.0.0/0" | "::/0");
    *action == "allow"
        && *direction == "in"
        && *sport == "any"
        && open(dst)
        && open(src)
        && proto_covers(proto, rule.proto)
        && in_range(dport, ':', rule.port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(port: u16, proto: Proto) -> PortRule {
        PortRule { port, proto }
    }

    #[test]
    fn a_port_inside_an_allowed_range_is_allowed() {
        let state = State {
            ports: vec![rule(22, Proto::Tcp)],
            other: vec![
                "port 1025-65535/tcp".into(),
                "allow udp 5000:6000 0.0.0.0/0 any 0.0.0.0/0 in".into(),
                "allow tcp 700:800 0.0.0.0/0 any 192.168.1.0/24 in".into(),
                "rule family=ipv4 accept".into(),
            ],
            ..State::default()
        };
        assert!(state.allows(rule(22, Proto::Tcp)));
        assert!(state.allows(rule(9099, Proto::Tcp)));
        assert_eq!(
            state.covering_range(rule(9099, Proto::Tcp)),
            Some("port 1025-65535/tcp")
        );
        assert!(!state.allows(rule(9099, Proto::Udp)));
        assert!(!state.allows(rule(80, Proto::Tcp)));
        assert!(state.allows(rule(5500, Proto::Udp)));
        // A range open to one network only does not let everyone in.
        assert!(!state.allows(rule(750, Proto::Tcp)));
    }
}
