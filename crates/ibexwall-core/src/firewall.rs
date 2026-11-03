// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reads the inbound firewall for the clients (`GetFirewall`): the same
//! detection and parsing the plugin plans from, over the real files (or
//! the sandbox root's), so what the UI shows is what the manager says.

use ibexwall_firewall::detect::{self, Reader};
use ibexwall_firewall::profile::{classify, recommend};
use ibexwall_firewall::{Backend, PortRule, State};
use ibexwall_proto::{FirewallNetwork, FirewallPort, FirewallState, names};

use crate::Core;

/// Files under the active root. A symlink counts as present even when its
/// target is missing (systemd's `invocation:<unit>` markers).
struct RootFiles {
    root: std::path::PathBuf,
}

impl Reader for RootFiles {
    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(names::path_under(&self.root, path)).ok()
    }

    fn exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(names::path_under(&self.root, path)).is_ok()
    }
}

fn port(rule: &PortRule) -> FirewallPort {
    FirewallPort {
        port: rule.port,
        proto: rule.proto.name().into(),
    }
}

fn convert(mut state: State) -> FirewallState {
    FirewallState {
        backend: state.backend.map_or("nftables", Backend::name).into(),
        active: state.active,
        zone: state.zone.take(),
        ports: state.ports.iter().map(port).collect(),
        services: state.services,
        listening: state.listening.iter().map(port).collect(),
        other: state.other,
        networks: vec![],
    }
}

pub async fn state(core: &Core) -> FirewallState {
    let reader = RootFiles {
        root: core.root.clone(),
    };
    let mut state = detect::read_state(&reader);
    if state.backend == Some(Backend::Nftables) {
        // Our own chain is the firewall: it is on when the chain exists,
        // and its allowed ports are the ones the plugin remembers.
        state.active = Some(
            core.engine
                .sys
                .nft
                .capture(names::FIREWALL_NFT_CHAIN)
                .ok()
                .flatten()
                .is_some(),
        );
        if let Some(saved) = reader.read(names::ARTIFACT_FIREWALL_SETTINGS)
            && let Ok(saved) = serde_json::from_str::<serde_json::Value>(&saved)
            && let Ok(ports) = serde_json::from_value::<Vec<PortRule>>(saved["ports"].clone())
        {
            state.ports = ports;
        }
    }
    let mut converted = convert(state);
    // NetworkManager is only asked on the real system: a sandbox root has
    // no business with the host's bus.
    if core.root == std::path::Path::new("/") {
        converted.networks = networks(&ibexwall_sys::nm::active_networks().await);
    }
    converted
}

/// The suggested profile for each real network (virtual links are left out).
pub fn networks(active: &[ibexwall_sys::nm::ActiveNetwork]) -> Vec<FirewallNetwork> {
    active
        .iter()
        .filter_map(|network| {
            let kind = classify(&network.nm_type, network.has_security)?;
            let recommendation = recommend(kind);
            Some(FirewallNetwork {
                name: network.name.clone(),
                kind: match kind {
                    ibexwall_firewall::profile::NetworkKind::Wired => "wired",
                    ibexwall_firewall::profile::NetworkKind::WifiSecured => "wifi_secured",
                    ibexwall_firewall::profile::NetworkKind::WifiOpen => "wifi_open",
                    ibexwall_firewall::profile::NetworkKind::Other => "other",
                }
                .into(),
                recommended: recommendation.profile.name().into(),
                warning: recommendation.warning.map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibexwall_firewall::Proto;

    #[test]
    fn the_unified_state_becomes_the_contract_type() {
        let converted = convert(State {
            backend: Some(Backend::Ufw),
            active: Some(true),
            zone: None,
            ports: vec![PortRule {
                port: 22,
                proto: Proto::Tcp,
            }],
            services: vec![],
            listening: vec![PortRule {
                port: 53,
                proto: Proto::Udp,
            }],
            other: vec!["deny tcp 23".into()],
        });
        assert_eq!(converted.backend, "ufw");
        assert_eq!(converted.ports[0].proto, "tcp");
        assert_eq!(converted.listening[0].port, 53);
        assert_eq!(converted.other, ["deny tcp 23"]);
        assert_eq!(convert(State::default()).backend, "nftables");
    }

    #[test]
    fn each_real_network_gets_a_suggestion_and_virtual_links_do_not() {
        use ibexwall_sys::nm::ActiveNetwork;
        let active = |name: &str, nm_type: &str, secured: bool| ActiveNetwork {
            name: name.into(),
            nm_type: nm_type.into(),
            has_security: secured,
        };
        let found = networks(&[
            active("Office LAN", "802-3-ethernet", false),
            active("Cafe", "802-11-wireless", false),
            active("Home", "802-11-wireless", true),
            active("corp", "vpn", false),
        ]);
        assert_eq!(found.len(), 3);
        assert_eq!(
            (found[0].kind.as_str(), found[0].recommended.as_str()),
            ("wired", "public")
        );
        assert_eq!(
            (found[1].kind.as_str(), found[1].recommended.as_str()),
            ("wifi_open", "travel")
        );
        assert_eq!(
            found[1].warning.as_deref(),
            Some("firewall-warning-open-network")
        );
        assert_eq!(found[2].warning, None);
    }
}
