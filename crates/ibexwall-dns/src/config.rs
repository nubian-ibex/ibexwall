// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolver configuration: where to listen and which encrypted upstreams
//! to use. Upstreams are always addressed by IP (bootstrap), so resolving
//! the resolver's own upstream never needs DNS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use ibexwall_proto::names;

use crate::lists::ListRef;
use crate::policy::{BlockResponse, Policy};
use serde::{Deserialize, Serialize};

/// Where the resolver listens by default (spec: loopback, own address).
pub fn default_listen() -> SocketAddr {
    let ip: IpAddr = names::DNS_BIND_ADDR
        .parse()
        .expect("DNS_BIND_ADDR is a valid IP address");
    SocketAddr::new(ip, names::DNS_BIND_PORT)
}

/// Encrypted transports only: a plaintext upstream would defeat the
/// product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// DNS over TLS (port 853).
    Tls,
    /// DNS over HTTPS (HTTP/2).
    Https,
    /// DNS over QUIC.
    Quic,
    /// DNS over HTTPS (HTTP/3).
    H3,
}

/// One upstream server: bootstrap IP plus the name its certificate must
/// match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    pub ip: IpAddr,
    pub server_name: String,
    pub transport: Transport,
    /// HTTP path for DoH and DoH3; defaults to `/dns-query`.
    #[serde(default)]
    pub path: Option<String>,
}

fn default_true() -> bool {
    true
}

/// The resolver's settings file, written by the `net.dns` plugin through
/// the core and read by `ibexwall-dns` at start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub servers: Vec<Server>,
    #[serde(default)]
    pub block_response: BlockResponse,
    /// Intercept the browser canary and known DoH endpoints.
    #[serde(default = "default_true")]
    pub block_doh: bool,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub doh_endpoints: Vec<String>,
    /// Block lists to load from the store and keep updated.
    #[serde(default)]
    pub lists: Vec<ListRef>,
    /// The known DNS-over-HTTPS endpoints list; its entries are refused
    /// while `block_doh` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_list: Option<ListRef>,
    /// Hours between list updates (jitter is added on top).
    #[serde(default = "default_update_hours")]
    pub update_interval_hours: u64,
}

fn default_update_hours() -> u64 {
    24
}

impl Settings {
    pub fn policy(&self) -> Policy {
        let mut policy = Policy::new(self.block_response, self.block_doh);
        policy.block(self.block.iter().cloned());
        policy.allow(self.allow.iter().cloned());
        policy.doh_endpoints(self.doh_endpoints.iter().cloned());
        policy
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("at least one upstream server is required")]
    NoUpstream,
    #[error("upstream `{0}`: server name must be a DNS name, not an IP or empty")]
    BadServerName(String),
    #[error("could not build the upstream resolver: {0}")]
    Resolver(String),
}

impl Server {
    fn validate(&self) -> Result<(), ConfigError> {
        let name = self.server_name.as_str();
        if name.is_empty() || name.parse::<IpAddr>().is_ok() || name.contains(char::is_whitespace) {
            return Err(ConfigError::BadServerName(self.ip.to_string()));
        }
        Ok(())
    }

    fn to_name_server(&self) -> NameServerConfig {
        let name: Arc<str> = Arc::from(self.server_name.as_str());
        let path: Option<Arc<str>> = self.path.as_deref().map(Arc::from);
        match self.transport {
            Transport::Tls => NameServerConfig::tls(self.ip, name),
            Transport::Https => NameServerConfig::https(self.ip, name, path),
            Transport::Quic => NameServerConfig::quic(self.ip, name),
            Transport::H3 => NameServerConfig::h3(self.ip, name, path),
        }
    }
}

/// Builds the forwarding resolver (DNSSEC validation stays off in the MVP,
/// see the F3 plan). Caching is on (it is what makes a
/// local stub fast); the hosts file is never consulted so the resolver
/// answers only what the network or the lists say.
pub fn build_resolver(servers: &[Server]) -> Result<Resolver<TokioRuntimeProvider>, ConfigError> {
    if servers.is_empty() {
        return Err(ConfigError::NoUpstream);
    }
    for server in servers {
        server.validate()?;
    }
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        servers.iter().map(Server::to_name_server).collect(),
    );
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    let options = builder.options_mut();
    options.use_hosts_file = ResolveHosts::Never;
    options.timeout = Duration::from_secs(3);
    options.attempts = 2;
    options.cache_size = 4096;
    builder
        .build()
        .map_err(|e| ConfigError::Resolver(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str) -> Server {
        Server {
            ip: "1.1.1.1".parse().unwrap(),
            server_name: name.into(),
            transport: Transport::Tls,
            path: None,
        }
    }

    #[test]
    fn rejects_no_upstream_and_bad_server_names() {
        assert!(matches!(build_resolver(&[]), Err(ConfigError::NoUpstream)));
        for bad in ["", "1.1.1.1", "two words"] {
            assert!(matches!(
                build_resolver(&[server(bad)]),
                Err(ConfigError::BadServerName(_))
            ));
        }
    }

    #[tokio::test]
    async fn builds_a_resolver_for_every_transport() {
        for transport in [
            Transport::Tls,
            Transport::Https,
            Transport::Quic,
            Transport::H3,
        ] {
            let mut s = server("one.one.one.one");
            s.transport = transport;
            assert!(build_resolver(&[s]).is_ok(), "{transport:?}");
        }
    }

    #[test]
    fn settings_reject_unknown_fields_and_apply_defaults() {
        let ok = r#"{ "servers": [{ "ip": "9.9.9.9", "server_name": "dns.quad9.net",
            "transport": "tls" }], "block": ["ads.example"] }"#;
        let settings: Settings = serde_json::from_str(ok).unwrap();
        assert_eq!(settings.listen, default_listen());
        assert!(settings.block_doh);
        assert_eq!(settings.policy().blocked_len(), 1);
        let bad = r#"{ "servers": [], "plaintext_upstream": true }"#;
        assert!(serde_json::from_str::<Settings>(bad).is_err());
    }

    #[test]
    fn server_round_trips_through_json() {
        let s = server("dns.quad9.net");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Server>(&json).unwrap(), s);
    }
}
