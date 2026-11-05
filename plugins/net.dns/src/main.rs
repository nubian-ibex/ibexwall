// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.dns`: secure DNS through the local resolver (`ibexwall-dns`).
//!
//! The plugin reads the machine, detects its DNS stack and proposes typed
//! operations; the core snapshots, applies and, if needed, rolls them
//! back. Nothing here writes to the system.

mod backend;
mod presets;

use std::collections::BTreeMap;

use backend::Backend;
use ibexwall_dns::config::{Server, Settings, Transport, default_listen};
use ibexwall_dns::lists::ListRef;
use ibexwall_dns::policy::BlockResponse;
use ibexwall_proto::{
    CheckOutcome, CheckReport, CheckResult, Finding, FindingStatus, Op, Severity, UnitAction, names,
};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Proto, Rule, Verdict};
use serde::Deserialize;
use serde_json::Value;

const ID: &str = "net.dns";
const SERVICE: &str = "ibexwall-dns.service";
const RESOLVED: &str = "systemd-resolved.service";
const CHECK_ID: &str = "dns.secure_resolver";

/// Known DNS-over-HTTPS endpoints, so browsers cannot route around the
/// stub while it is on (HaGeZi's Encrypted DNS Bypass list, GPL-3.0,
/// consulted 2026-11-02).
const DOH_ENDPOINTS_URL: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt";
const DOH_ENDPOINTS_ID: &str = "doh_endpoints";

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(SecureDns)) {
        eprintln!("ibexwall-plugin-dns: {err}");
        std::process::exit(1);
    }
}

/// What the user chose, as the UI and CLI send it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    provider: String,
    transport: Transport,
    /// Custom upstreams; when present they replace the provider. The order
    /// is the failover: the first answers, the next ones take over. A
    /// `plain` server is allowed only on a local-network address (a router,
    /// a corporate resolver, a VPN's DNS).
    servers: Vec<Server>,
    /// Split DNS: domains answered by other servers, for example the
    /// corporate zone by the corporate resolver.
    routes: Vec<ibexwall_dns::config::Route>,
    lists: Vec<ListRef>,
    /// One block list by preset id, for the command line
    /// (`ibexctl plan net.dns --set list=oisd-small`).
    #[serde(default)]
    list: Option<String>,
    block_response: BlockResponse,
    block_doh: bool,
    allow: Vec<String>,
    /// Refuse clear DNS (port 53) and DoT (port 853) from everyone but
    /// the resolver.
    enforcement: bool,
    /// Explicit consent to set the browser policy that turns each
    /// browser's own DoH off (never implied by other choices).
    browser_policies: bool,
    /// `restore` (default) or `block`: what happens if the resolver cannot
    /// stay up.
    on_failure: ibexwall_dns::config::FailureMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: "quad9".into(),
            transport: Transport::Tls,
            servers: vec![],
            routes: vec![],
            lists: vec![],
            block_response: BlockResponse::default(),
            block_doh: true,
            allow: vec![],
            enforcement: true,
            browser_policies: false,
            on_failure: ibexwall_dns::config::FailureMode::default(),
            list: None,
        }
    }
}

impl Config {
    fn parse(value: Value) -> Result<Self, PluginError> {
        if value.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(value).map_err(|e| PluginError::invalid("config", e.to_string()))
    }

    fn upstreams(&self) -> Result<Vec<Server>, PluginError> {
        if !self.servers.is_empty() {
            return Ok(self.servers.clone());
        }
        let provider = presets::provider(&self.provider).ok_or_else(|| {
            PluginError::invalid("provider", format!("unknown `{}`", self.provider))
        })?;
        provider.servers(self.transport).ok_or_else(|| {
            PluginError::invalid(
                "transport",
                format!("{} does not document {:?}", provider.name, self.transport),
            )
        })
    }

    fn settings(&self) -> Result<Settings, PluginError> {
        let mut lists = self.lists.clone();
        if let Some(list) = &self.list
            && !lists.iter().any(|entry| &entry.id == list)
        {
            lists.push(ListRef {
                id: list.clone(),
                url: None,
            });
        }
        for list in &lists {
            list.resolve()
                .map_err(|e| PluginError::invalid("lists", e.to_string()))?;
        }
        let settings = Settings {
            listen: default_listen(),
            servers: self.upstreams()?,
            routes: self.routes.clone(),
            block_response: self.block_response,
            block_doh: self.block_doh,
            block: vec![],
            allow: self.allow.clone(),
            doh_endpoints: vec![],
            on_failure: self.on_failure,
            lists,
            doh_list: self.block_doh.then(|| ListRef {
                id: DOH_ENDPOINTS_ID.into(),
                url: Some(DOH_ENDPOINTS_URL.into()),
            }),
            update_interval_hours: 24,
        };
        settings
            .validate()
            .map_err(|e| PluginError::invalid("servers", e.to_string()))?;
        Ok(settings)
    }
}

struct SecureDns;

impl Plugin for SecureDns {
    fn id(&self) -> &'static str {
        ID
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(evaluate(&Sandbox::system()))
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        plan(&Sandbox::system(), Config::parse(config)?)
    }

    async fn verify(&self, _transaction: &str, _ops: &[Op]) -> bool {
        evaluate(&Sandbox::system())
            .results
            .iter()
            .all(|r| r.outcome == CheckOutcome::Pass)
    }
}

fn dropin_content() -> String {
    // FallbackDNS= (empty) removes resolved's built-in plain-text public
    // servers, so a dead local resolver can never leak queries.
    format!(
        "# Managed by IbexWall (net.dns). Remove this file to restore the previous behavior.\n\
         [Resolve]\nDNS={}\nDomains=~.\nFallbackDNS=\n",
        names::DNS_BIND_ADDR
    )
}

fn plan(sandbox: &Sandbox, config: Config) -> Result<Vec<Op>, PluginError> {
    match backend::detect(sandbox) {
        Backend::Resolved => {}
        Backend::Unsupported(reason) => return Err(PluginError::invalid("backend", reason)),
    }
    let settings = config.settings()?;
    let settings_json = serde_json::to_string_pretty(&settings)
        .map_err(|e| PluginError::invalid("settings", e.to_string()))?;
    let settings_path = names::ARTIFACT_DNS_SETTINGS.to_string();
    let write = |path: String, content: String| Op::FileWrite {
        path,
        content,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    };
    let mut ops = vec![
        write(settings_path, format!("{settings_json}\n")),
        write(names::ARTIFACT_RESOLVED.into(), dropin_content()),
        // The resolver must be up before resolved is pointed at it.
        Op::SystemdUnit {
            unit: SERVICE.into(),
            action: UnitAction::Enable,
            now: Some(true),
        },
        Op::SystemdUnit {
            unit: RESOLVED.into(),
            action: UnitAction::Restart,
            now: None,
        },
    ];
    // Last, so a failure above can never leave clear DNS blocked with no
    // resolver to answer.
    if config.enforcement {
        ops.push(enforcement_op(sandbox)?);
    }
    if config.browser_policies {
        ops.extend(browser_policy_ops(sandbox));
    }
    Ok(ops)
}

/// Browsers we can steer, with the executables that reveal they are
/// installed. Only installed browsers get a policy file.
const BROWSER_EXECUTABLES: &[(&str, &[&str])] = &[
    ("firefox", &["firefox", "firefox-esr"]),
    ("chrome", &["google-chrome", "google-chrome-stable"]),
    ("chromium", &["chromium", "chromium-browser-bin"]),
    ("chromium-browser", &["chromium-browser"]),
    ("brave", &["brave-browser", "brave"]),
    ("edge", &["microsoft-edge", "microsoft-edge-stable"]),
];

fn installed_browsers(sandbox: &Sandbox) -> Vec<&'static str> {
    BROWSER_EXECUTABLES
        .iter()
        .filter(|&(_, executables)| {
            executables
                .iter()
                .any(|name| sandbox.exists(&format!("/usr/bin/{name}")))
        })
        .map(|(browser, _)| *browser)
        .collect()
}

/// One op per installed browser: exactly the DoH-off policy the core
/// accepts, in the file that browser's documentation defines.
fn browser_policy_ops(sandbox: &Sandbox) -> Vec<Op> {
    installed_browsers(sandbox)
        .into_iter()
        .filter_map(|browser| {
            ibexwall_sys::browser::doh_off(browser).map(|policy| Op::BrowserPolicy {
                browser: browser.into(),
                policy,
            })
        })
        .collect()
}

/// Looks up a user's uid in `/etc/passwd` (read-only).
fn uid_of(sandbox: &Sandbox, user: &str) -> Option<u32> {
    sandbox.read("/etc/passwd")?.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(user)).then(|| fields.nth(1)?.parse().ok())?
    })
}

/// Refuse clear DNS and DoT from every user except the resolver. Loopback
/// stays open so applications can reach the local stub.
fn enforcement_op(sandbox: &Sandbox) -> Result<Op, PluginError> {
    let uid = uid_of(sandbox, names::DNS_USER).ok_or_else(|| {
        PluginError::invalid(
            "enforcement",
            format!("the `{}` user does not exist", names::DNS_USER),
        )
    })?;
    let guard = Fragment {
        chains: vec![Chain {
            name: names::DNS_NFT_CHAIN.into(),
            priority: 0,
            hook: Default::default(),
            rules: vec![
                Rule {
                    iif_loopback: false,
                    iif_prefix: None,
                    oif_prefix: None,
                    saddr: vec![],
                    daddr: vec![],
                    ct_established: false,
                    ct_new: false,
                    mark: None,
                    icmp: false,
                    oif_loopback: true,
                    uid_not: None,
                    protocols: vec![],
                    dports: vec![],
                    verdict: Verdict::Accept,
                },
                Rule {
                    iif_loopback: false,
                    iif_prefix: None,
                    oif_prefix: None,
                    saddr: vec![],
                    daddr: vec![],
                    ct_established: false,
                    ct_new: false,
                    mark: None,
                    icmp: false,
                    oif_loopback: false,
                    uid_not: Some(uid),
                    protocols: vec![Proto::Udp, Proto::Tcp],
                    dports: vec![53, 853],
                    verdict: Verdict::Reject,
                },
            ],
        }],
    };
    Ok(Op::NftFragment {
        fragment: serde_json::to_value(guard)
            .map_err(|e| PluginError::invalid("enforcement", e.to_string()))?,
    })
}

/// `/proc/net/udp` lists a local address as little-endian hex.
fn listening_hex() -> String {
    let address: std::net::Ipv4Addr = names::DNS_BIND_ADDR
        .parse()
        .expect("DNS_BIND_ADDR is an IPv4 address");
    format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.octets()),
        names::DNS_BIND_PORT
    )
}

fn resolver_listening(sandbox: &Sandbox) -> bool {
    let wanted = listening_hex();
    sandbox.read("/proc/net/udp").is_some_and(|table| {
        table
            .lines()
            .any(|l| l.split_whitespace().nth(1) == Some(&wanted))
    })
}

fn dropin_points_at_resolver(sandbox: &Sandbox) -> bool {
    sandbox.read(names::ARTIFACT_RESOLVED).is_some_and(|text| {
        text.lines()
            .any(|l| l.trim() == format!("DNS={}", names::DNS_BIND_ADDR))
    })
}

fn info_finding(id: &str, title: &str, summary: &str, servers: &[String]) -> Finding {
    Finding {
        id: id.into(),
        plugin: ID.into(),
        severity: Severity::Info,
        title_key: title.into(),
        summary_key: summary.into(),
        args: BTreeMap::from([("servers".to_string(), servers.join(", "))]),
        references: vec![],
        remediation: None,
        status: FindingStatus::Open,
        detected_at: "1970-01-01T00:00:00Z".into(),
    }
}

/// The DNS servers the network handed this machine (DHCP, a VPN), as the
/// system resolver sees them: IbexWall's own address and loopback excluded.
fn network_servers(sandbox: &Sandbox) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in [
        "/run/systemd/resolve/resolv.conf",
        "/run/NetworkManager/resolv.conf",
    ] {
        let Some(text) = sandbox.read(path) else {
            continue;
        };
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("nameserver") else {
                continue;
            };
            let address = rest.trim();
            let Ok(ip) = address.parse::<std::net::IpAddr>() else {
                continue;
            };
            if ip.is_loopback()
                || address == names::DNS_BIND_ADDR
                || out.iter().any(|s| s == address)
            {
                continue;
            }
            out.push(address.to_string());
        }
    }
    out
}

/// Upstreams in IbexWall's own settings that are not encrypted.
fn plain_upstreams(sandbox: &Sandbox) -> Vec<String> {
    let Some(text) = sandbox.read(names::ARTIFACT_DNS_SETTINGS) else {
        return vec![];
    };
    let Ok(settings) = serde_json::from_str::<Settings>(&text) else {
        return vec![];
    };
    settings
        .servers
        .iter()
        .chain(settings.routes.iter().flat_map(|r| r.servers.iter()))
        .filter(|s| s.transport == Transport::Plain)
        .map(|s| s.ip.to_string())
        .collect()
}

/// Runs against any tree (real system, sandbox or fixture).
fn evaluate(sandbox: &Sandbox) -> CheckReport {
    let backend = backend::detect(sandbox);
    let outcome = match backend {
        Backend::Unsupported(_) => CheckOutcome::NotAssessed,
        Backend::Resolved if dropin_points_at_resolver(sandbox) && resolver_listening(sandbox) => {
            CheckOutcome::Pass
        }
        Backend::Resolved => CheckOutcome::Fail,
    };
    let mut findings = vec![];
    // What the person should know about where their DNS goes, said plainly
    // and never as a failure: the network's own servers, and a plain
    // upstream on a local network.
    let network = network_servers(sandbox);
    if !network.is_empty() {
        findings.push(info_finding(
            "dns.network_servers",
            "dns-network-servers-title",
            "dns-network-servers-summary",
            &network,
        ));
    }
    let plain = plain_upstreams(sandbox);
    if !plain.is_empty() {
        findings.push(info_finding(
            "dns.plain_upstream",
            "dns-plain-upstream-title",
            "dns-plain-upstream-summary",
            &plain,
        ));
    }
    if outcome == CheckOutcome::Fail {
        findings.push(Finding {
            id: CHECK_ID.into(),
            plugin: ID.into(),
            severity: Severity::Medium,
            title_key: "dns-unprotected-title".into(),
            summary_key: "dns-unprotected-summary".into(),
            args: BTreeMap::new(),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: "1970-01-01T00:00:00Z".into(),
        });
    }
    CheckReport {
        results: vec![CheckResult {
            id: CHECK_ID.into(),
            severity: Severity::Medium,
            outcome,
        }],
        findings,
    }
}

#[cfg(test)]
mod tests;
