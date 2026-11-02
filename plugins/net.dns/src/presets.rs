// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Upstream providers. Every fact has a source and a consultation date;
//! a provider is added only after its own documentation was read.

use std::net::IpAddr;

use ibexwall_dns::config::{Server, Transport};

// The jurisdiction, sources and consultation date are shown by the DNS
// screen (F3 M7, docs/plans/F3-secure-dns.md); until then tests read them.
#[cfg_attr(not(test), allow(dead_code))]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    /// Bootstrap IPv4 addresses (IPv6 joins once connectivity probing exists).
    pub addresses: &'static [&'static str],
    /// Certificate name the upstream must present.
    pub server_name: &'static str,
    pub transports: &'static [Transport],
    pub jurisdiction: &'static str,
    /// Where the provider documents its logging and addresses.
    pub sources: &'static [&'static str],
    pub consulted: &'static str,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "quad9",
        name: "Quad9",
        addresses: &["9.9.9.9", "149.112.112.112"],
        server_name: "dns.quad9.net",
        transports: &[
            Transport::Tls,
            Transport::Https,
            Transport::Quic,
            Transport::H3,
        ],
        jurisdiction: "CH",
        sources: &[
            "https://quad9.net/service/service-addresses-and-features/",
            "https://quad9.net/privacy/policy/",
        ],
        consulted: "2026-11-02",
    },
    Provider {
        id: "cloudflare",
        name: "Cloudflare",
        addresses: &["1.1.1.1", "1.0.0.1"],
        server_name: "one.one.one.one",
        // DoQ is not offered: the probe timed out (ADR-0028).
        transports: &[Transport::Tls, Transport::Https, Transport::H3],
        jurisdiction: "US",
        sources: &["https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/"],
        consulted: "2026-11-02",
    },
];

pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.id == id)
}

impl Provider {
    /// The servers for one transport, or `None` if the provider does not
    /// document that transport.
    pub fn servers(&self, transport: Transport) -> Option<Vec<Server>> {
        if !self.transports.contains(&transport) {
            return None;
        }
        Some(
            self.addresses
                .iter()
                .map(|address| Server {
                    ip: address.parse::<IpAddr>().expect("preset address is an IP"),
                    server_name: self.server_name.into(),
                    transport,
                    path: None,
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_is_well_formed_and_sourced() {
        for provider in PROVIDERS {
            assert!(!provider.sources.is_empty(), "{}", provider.id);
            assert!(
                provider.jurisdiction.len() == 2
                    && provider
                        .jurisdiction
                        .bytes()
                        .all(|b| b.is_ascii_uppercase()),
                "{}: jurisdiction is an ISO country code",
                provider.id
            );
            let date: Vec<&str> = provider.consulted.split('-').collect();
            assert_eq!(
                date.iter().map(|part| part.len()).collect::<Vec<_>>(),
                [4, 2, 2],
                "{}: consulted is YYYY-MM-DD",
                provider.id
            );
            assert!(provider.sources.iter().all(|s| s.starts_with("https://")));
            assert!(
                provider
                    .addresses
                    .iter()
                    .all(|a| a.parse::<IpAddr>().is_ok())
            );
            assert!(provider.server_name.parse::<IpAddr>().is_err());
            for transport in provider.transports {
                assert!(provider.servers(*transport).is_some());
            }
        }
    }

    #[test]
    fn undocumented_transports_are_refused() {
        let cloudflare = provider("cloudflare").unwrap();
        assert!(cloudflare.servers(Transport::Quic).is_none());
        assert_eq!(cloudflare.servers(Transport::Tls).unwrap().len(), 2);
    }
}
