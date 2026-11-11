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

/// Encrypted transports for the Internet; `Plain` exists only for resolvers
/// on this machine's own networks (a router, a corporate server, a VPN's
/// DNS) and is refused for any public address, so a plaintext upstream can
/// never carry a query across the Internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Plain DNS (UDP and TCP, port 53) to a local-network address.
    Plain,
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
    /// The name the certificate must match; empty for `plain`.
    #[serde(default)]
    pub server_name: String,
    pub transport: Transport,
    /// HTTP path for DoH and DoH3; defaults to `/dns-query`.
    #[serde(default)]
    pub path: Option<String>,
}

/// Addresses that cannot be reached across the public Internet: private
/// ranges, loopback, link-local, unique local, and the carrier-grade NAT
/// block VPNs such as Tailscale use.
pub fn is_local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (a == 100 && (64..=127).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// A name or a domain: lowercase labels of letters, digits and `-`.
pub fn is_domain(text: &str) -> bool {
    let text = text.trim_end_matches('.');
    !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Queries under these domains go to their own servers (split DNS: the
/// corporate zone to the corporate resolver, everything else to the
/// default servers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub domains: Vec<String>,
    pub servers: Vec<Server>,
}

fn default_true() -> bool {
    true
}

/// What happens when the resolver cannot stay up (spec section 4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// Remove the drop-in and the guard chain: DNS works again, in the
    /// clear (the default).
    #[default]
    Restore,
    /// Keep enforcement: no DNS at all rather than clear DNS.
    Block,
}

/// The resolver's settings file, written by the `net.dns` plugin through
/// the core and read by `ibexwall-dns` at start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The default upstreams, in order: the first answers, the next ones
    /// take over when it does not.
    pub servers: Vec<Server>,
    /// Domains answered by other servers (split DNS).
    #[serde(default)]
    pub routes: Vec<Route>,
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
    /// What the failsafe does when the resolver cannot stay up.
    #[serde(default)]
    pub on_failure: FailureMode,
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
    /// What the person chose (provider, transport, list, ...), kept beside
    /// the settings it produced so the app can show what is applied. The
    /// resolver ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice: Option<serde_json::Value>,
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
    #[error("upstream `{0}`: plain DNS is only allowed for local-network addresses")]
    PublicPlain(String),
    #[error("`{0}` is not a valid domain")]
    BadDomain(String),
    #[error(
        "`listen` must be a loopback address, got `{0}` (a non-loopback listen would make the resolver open)"
    )]
    BadListen(String),
    #[error("could not build the upstream resolver: {0}")]
    Resolver(String),
}

impl Server {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.transport == Transport::Plain {
            return if is_local_address(self.ip) {
                Ok(())
            } else {
                Err(ConfigError::PublicPlain(self.ip.to_string()))
            };
        }
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
            Transport::Plain => NameServerConfig::udp_and_tcp(self.ip),
            Transport::Tls => NameServerConfig::tls(self.ip, name),
            Transport::Https => NameServerConfig::https(self.ip, name, path),
            Transport::Quic => NameServerConfig::quic(self.ip, name),
            Transport::H3 => NameServerConfig::h3(self.ip, name, path),
        }
    }
}

impl Settings {
    /// The default servers and every route must be valid and local-only
    /// where they are plain.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // The resolver is a local stub; a non-loopback listen would turn
        // it into an open resolver and an amplification source.
        if !self.listen.ip().is_loopback() {
            return Err(ConfigError::BadListen(self.listen.to_string()));
        }
        if self.servers.is_empty() {
            return Err(ConfigError::NoUpstream);
        }
        for server in &self.servers {
            server.validate()?;
        }
        for route in &self.routes {
            if route.servers.is_empty() {
                return Err(ConfigError::NoUpstream);
            }
            for domain in &route.domains {
                if !is_domain(domain) {
                    return Err(ConfigError::BadDomain(domain.clone()));
                }
            }
            for server in &route.servers {
                server.validate()?;
            }
        }
        Ok(())
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

    fn plain(ip: &str) -> Server {
        Server {
            ip: ip.parse().unwrap(),
            server_name: String::new(),
            transport: Transport::Plain,
            path: None,
        }
    }

    #[test]
    fn plain_dns_is_for_local_networks_only() {
        for local in [
            "192.168.1.1",
            "10.0.0.2",
            "172.16.5.5",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_local_address(local.parse().unwrap()), "{local}");
        }
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "2001:4860:4860::8888",
            "172.32.0.1",
        ] {
            assert!(!is_local_address(public.parse().unwrap()), "{public}");
        }
    }

    #[tokio::test]
    async fn a_plain_upstream_builds_for_a_private_address_and_never_for_a_public_one() {
        assert!(build_resolver(&[plain("192.168.1.1")]).is_ok());
        // A secondary of another kind next to it: the order is the failover.
        assert!(build_resolver(&[plain("10.0.0.2"), server("dns.quad9.net")]).is_ok());
        assert!(matches!(
            build_resolver(&[plain("8.8.8.8")]),
            Err(ConfigError::PublicPlain(_))
        ));
    }

    #[test]
    fn routes_need_servers_and_real_domains() {
        let ok = r#"{ "servers": [{ "ip": "9.9.9.9", "server_name": "dns.quad9.net", "transport": "tls" }],
            "routes": [{ "domains": ["corp.example", "internal."], "servers": [{ "ip": "10.0.0.2", "transport": "plain" }] }] }"#;
        let settings: Settings = serde_json::from_str(ok).unwrap();
        settings.validate().unwrap();
        for bad in [
            r#"{ "servers": [], "routes": [{ "domains": ["Bad_Name"], "servers": [{ "ip": "10.0.0.2", "transport": "plain" }] }] }"#,
            r#"{ "servers": [], "routes": [{ "domains": ["corp.example"], "servers": [] }] }"#,
            r#"{ "servers": [], "routes": [{ "domains": ["corp.example"], "servers": [{ "ip": "8.8.8.8", "transport": "plain" }] }] }"#,
            r#"{ "servers": [], "routes": [{ "domains": ["a b.example"], "servers": [{ "ip": "10.0.0.2", "transport": "plain" }] }] }"#,
        ] {
            let settings: Settings = serde_json::from_str(bad).unwrap();
            assert!(settings.validate().is_err(), "{bad}");
        }
        assert!(
            is_domain("corp.example")
                && is_domain("a-b.c1.example.")
                && !is_domain("")
                && !is_domain("-a.example")
                && !is_domain("a..b")
        );
    }

    #[test]
    fn server_round_trips_through_json() {
        let s = server("dns.quad9.net");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Server>(&json).unwrap(), s);
    }
}
