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
