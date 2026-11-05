// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net.firewall`: who can reach this computer. The plugin proposes typed
//! operations; the core executes them and can roll them back.
//!
//! - With firewalld or ufw running, it asks that manager (through
//!   `firewall.adapter`), so the change shows up natively.
//! - With neither, it can offer basic inbound protection in IbexWall's own
//!   table: established traffic, loopback, ICMP, DHCP, container and VPN
//!   interfaces, the ports the user allows, and a drop for the rest.
//!
//! Config (`ibexctl plan net.firewall --set allow=8080/tcp`): `allow`,
//! `remove`, `allow_service`, `remove_service` (a string or a list; a port
//! is `8080/tcp`, tcp when no protocol is given), `enable_basic`,
//! `allow_listening`, `mdns`.

use std::collections::BTreeSet;

use ibexwall_firewall::detect::{self, Reader};
use ibexwall_firewall::profile::Profile;
use ibexwall_firewall::{Backend, FirewallAction, PortRule, Proto};
use ibexwall_proto::{CheckReport, Op, names};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_sys::nft::{Chain, Fragment, Hook, Rule, Verdict};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// The plugin's entry point: the multicall binary calls it, and a plugin runs
/// as its own process (ADR-0041).
pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Firewall)) {
        eprintln!("ibexwall-plugin-firewall: {err}");
        std::process::exit(1);
    }
}

struct Firewall;

/// A string or a list of strings, so `--set allow=22` and a list both work.
fn many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
        Number(u64),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(text) => vec![text],
        OneOrMany::Many(list) => list,
        OneOrMany::Number(number) => vec![number.to_string()],
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    #[serde(deserialize_with = "many")]
    allow: Vec<String>,
    #[serde(deserialize_with = "many")]
    remove: Vec<String>,
    #[serde(deserialize_with = "many")]
    allow_service: Vec<String>,
    #[serde(deserialize_with = "many")]
    remove_service: Vec<String>,
    /// Turn on IbexWall's own inbound protection (when no manager exists).
    enable_basic: bool,
    /// When enabling basic protection, keep the TCP services that are
    /// listening now reachable, so an SSH session is not lost.
    allow_listening: bool,
    /// Allow multicast DNS (service discovery on the local network).
    mdns: bool,
    /// `home`, `work`, `public` or `travel`: the zone firewalld applies to
    /// networks without one (firewalld only).
    profile: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allow: vec![],
            remove: vec![],
            allow_service: vec![],
            remove_service: vec![],
            enable_basic: false,
            allow_listening: true,
            mdns: false,
            profile: None,
        }
    }
}

/// What the plugin keeps when it owns the firewall itself.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Settings {
    ports: Vec<PortRule>,
    #[serde(default)]
    mdns: bool,
}

struct Files<'a>(&'a Sandbox);

impl Reader for Files<'_> {
    fn read(&self, path: &str) -> Option<String> {
        self.0.read(path)
    }
    // systemd's `invocation:<unit>` markers are symlinks whose target does
    // not exist: they count as present.
    fn exists(&self, path: &str) -> bool {
        self.0.exists(path) || self.0.read_link(path).is_some()
    }
}

impl Plugin for Firewall {
    fn id(&self) -> &'static str {
        "net.firewall"
    }

    /// The posture plugin already scores "is a firewall running"; this one
    /// reports nothing of its own, so the score is not counted twice.
    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![],
            findings: vec![],
        })
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), config)
    }

    async fn verify(&self, _transaction: &str, ops: &[Op]) -> bool {
        verify(&Sandbox::system(), ops)
    }
}

/// `8080/tcp`, `53/udp` or `8080` (tcp).
fn parse_port(text: &str) -> Result<PortRule, PluginError> {
    let (port, proto) = match text.split_once('/') {
        Some((port, proto)) => (port, proto),
        None => (text, "tcp"),
    };
    let proto = Proto::parse(&proto.to_ascii_lowercase()).ok_or_else(|| {
        PluginError::invalid("port", format!("`{text}`: the protocol is tcp or udp"))
    })?;
    match port.trim().parse::<u16>() {
        Ok(port) if port != 0 => Ok(PortRule { port, proto }),
        _ => Err(PluginError::invalid(
            "port",
            format!("`{text}` is not a port between 1 and 65535"),
        )),
    }
}

fn adapter_op(backend: Backend, action: &FirewallAction) -> Result<Op, PluginError> {
    ibexwall_firewall::validate(backend, action)
        .map_err(|e| PluginError::invalid("action", e.to_string()))?;
    Ok(Op::FirewallAdapter {
        backend: backend.name().into(),
        action: serde_json::to_value(action)
            .map_err(|e| PluginError::invalid("action", e.to_string()))?,
    })
}

fn plan(sandbox: &Sandbox, config: Config) -> Result<Vec<Op>, PluginError> {
    let reader = Files(sandbox);
    let (backend, active) = detect::detect(&reader);
    match backend {
        Backend::Firewalld | Backend::Ufw => {
            if active != Some(true) {
                return Err(PluginError::invalid(
                    "backend",
                    format!(
                        "{} is installed but not running; start it first",
                        backend.name()
                    ),
                ));
            }
            plan_manager(backend, &reader, &config)
        }
        Backend::Nftables => plan_basic(sandbox, &reader, config),
    }
}

fn plan_manager(
    backend: Backend,
    reader: &Files<'_>,
    config: &Config,
) -> Result<Vec<Op>, PluginError> {
    let mut ops = Vec::new();
    if let Some(name) = &config.profile {
        let profile = Profile::parse(name).ok_or_else(|| {
            PluginError::invalid(
                "profile",
                format!("`{name}` is not a profile: home, work, public or travel"),
            )
        })?;
        if backend != Backend::Firewalld {
            return Err(PluginError::invalid(
                "profile",
                "profiles map to firewalld zones; they are not available with ufw".to_string(),
            ));
        }
        let zone = profile.zone();
        let exists = reader.exists(&format!("/etc/firewalld/zones/{zone}.xml"))
            || reader.exists(&format!("/usr/lib/firewalld/zones/{zone}.xml"));
        if !exists {
            return Err(PluginError::invalid(
                "profile",
                format!("this firewalld has no `{zone}` zone for the {name} profile"),
            ));
        }
        ops.push(adapter_op(
            backend,
            &FirewallAction::SetDefaultZone { name: zone.into() },
        )?);
    }
    for text in &config.allow {
        let PortRule { port, proto } = parse_port(text)?;
        ops.push(adapter_op(
            backend,
            &FirewallAction::AllowPort {
                port,
                proto,
                zone: None,
            },
        )?);
    }
    for text in &config.remove {
        let PortRule { port, proto } = parse_port(text)?;
        ops.push(adapter_op(
            backend,
            &FirewallAction::RemovePort {
                port,
                proto,
                zone: None,
            },
        )?);
    }
    for name in &config.allow_service {
        ops.push(adapter_op(
            backend,
            &FirewallAction::AllowService {
                name: name.clone(),
                zone: None,
            },
        )?);
    }
    for name in &config.remove_service {
        ops.push(adapter_op(
            backend,
            &FirewallAction::RemoveService {
                name: name.clone(),
                zone: None,
            },
        )?);
    }
    if ops.is_empty() {
        return Err(PluginError::invalid(
            "allow",
            "nothing to change: name a port or service to allow or remove".to_string(),
        ));
    }
    Ok(ops)
}

/// Traffic from these interfaces is container, VM or VPN plumbing, not
/// other computers on the network; the basic protection leaves it alone.
const TRUSTED_INTERFACE_PREFIXES: &[&str] = &[
    "docker",
    "br-",
    "veth",
    "virbr",
    "podman",
    "cni",
    "tailscale",
    "wg",
    "wt",
    "nb-",
    "tun",
];

fn plan_basic(
    sandbox: &Sandbox,
    reader: &Files<'_>,
    config: Config,
) -> Result<Vec<Op>, PluginError> {
    if config.profile.is_some() {
        return Err(PluginError::invalid(
            "profile",
            "profiles map to firewalld zones; they are not available here".to_string(),
        ));
    }
    if !config.allow_service.is_empty() || !config.remove_service.is_empty() {
        return Err(PluginError::invalid(
            "allow_service",
            "services need firewalld; with the basic protection allow ports".to_string(),
        ));
    }
    let existing: Option<Settings> = sandbox
        .read(names::ARTIFACT_FIREWALL_SETTINGS)
        .and_then(|text| serde_json::from_str(&text).ok());
    if existing.is_none() && !config.enable_basic {
        return Err(PluginError::invalid(
            "enable_basic",
            "no firewall manager is running; set enable_basic=true to turn on basic inbound protection"
                .to_string(),
        ));
    }
    let first_time = existing.is_none();
    let mut settings = existing.unwrap_or_default();
    let mut ports: BTreeSet<PortRule> = settings.ports.iter().copied().collect();
    if first_time && config.allow_listening {
        // Do not cut the session the user is in: services listening now
        // stay reachable until they say otherwise.
        let state = detect::read_state(reader);
        ports.extend(state.listening.iter().filter(|p| p.proto == Proto::Tcp));
    }
    for text in &config.allow {
        ports.insert(parse_port(text)?);
    }
    for text in &config.remove {
        ports.remove(&parse_port(text)?);
    }
    settings.ports = ports.into_iter().collect();
    if config.mdns || first_time {
        settings.mdns = config.mdns;
    }

    let fragment = serde_json::to_value(basic_chain(&settings))
        .map_err(|e| PluginError::invalid("fragment", e.to_string()))?;
    let body = serde_json::to_string_pretty(&settings)
        .map_err(|e| PluginError::invalid("settings", e.to_string()))?;
    Ok(vec![
        Op::FileWrite {
            path: names::ARTIFACT_FIREWALL_SETTINGS.into(),
            content: format!("{body}\n"),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        },
        Op::NftFragment { fragment },
    ])
}

fn accept(configure: impl FnOnce(&mut Rule)) -> Rule {
    let mut rule = Rule {
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
        uid_not: None,
        protocols: vec![],
        dports: vec![],
        verdict: Verdict::Accept,
    };
    configure(&mut rule);
    rule
}

fn to_proto(proto: Proto) -> ibexwall_sys::nft::Proto {
    match proto {
        Proto::Tcp => ibexwall_sys::nft::Proto::Tcp,
        Proto::Udp => ibexwall_sys::nft::Proto::Udp,
    }
}

/// The input chain (spec appendix E), plus the user's ports.
fn basic_chain(settings: &Settings) -> Fragment {
    let mut rules = vec![
        accept(|r| r.ct_established = true),
        accept(|r| r.iif_loopback = true),
        accept(|r| r.icmp = true),
        // DHCP and DHCPv6 clients.
        accept(|r| {
            r.protocols = vec![ibexwall_sys::nft::Proto::Udp];
            r.dports = vec![68, 546];
        }),
    ];
    for prefix in TRUSTED_INTERFACE_PREFIXES {
        rules.push(accept(|r| r.iif_prefix = Some((*prefix).to_string())));
    }
    if settings.mdns {
        rules.push(accept(|r| {
            r.protocols = vec![ibexwall_sys::nft::Proto::Udp];
            r.dports = vec![5353];
        }));
    }
    for proto in [Proto::Tcp, Proto::Udp] {
        let wanted: Vec<u16> = settings
            .ports
            .iter()
            .filter(|p| p.proto == proto)
            .map(|p| p.port)
            .collect();
        // A rule takes at most 16 ports.
        for chunk in wanted.chunks(16) {
            rules.push(accept(|r| {
                r.protocols = vec![to_proto(proto)];
                r.dports = chunk.to_vec();
            }));
        }
    }
    rules.push(Rule {
        verdict: Verdict::Drop,
        ..accept(|_| {})
    });
    Fragment {
        chains: vec![Chain {
            name: names::FIREWALL_NFT_CHAIN.into(),
            priority: 5,
            hook: Hook::Input,
            rules,
        }],
    }
}

/// After the core applied `ops`, does the manager's own state agree?
fn verify(sandbox: &Sandbox, ops: &[Op]) -> bool {
    let state = detect::read_state(&Files(sandbox));
    ops.iter().all(|op| {
        let Op::FirewallAdapter { action, .. } = op else {
            return true;
        };
        match serde_json::from_value::<FirewallAction>(action.clone()) {
            Ok(FirewallAction::AllowPort { port, proto, .. }) => {
                state.ports.contains(&PortRule { port, proto })
            }
            Ok(FirewallAction::RemovePort { port, proto, .. }) => {
                !state.ports.contains(&PortRule { port, proto })
            }
            Ok(FirewallAction::AllowService { name, .. }) => state.services.contains(&name),
            Ok(FirewallAction::RemoveService { name, .. }) => !state.services.contains(&name),
            Ok(FirewallAction::SetDefaultZone { name }) => {
                state.zone.as_deref() == Some(name.as_str())
            }
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "ibx-fw-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    fn config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).unwrap()
    }

    const FIREWALLD: (&str, &str) = ("/run/systemd/units/invocation:firewalld.service", "");
    const HEADER: &str = "  sl  local_address rem_address   st tx_queue\n";

    #[test]
    fn firewalld_gets_one_typed_op_per_change() {
        let (root, sandbox) = tree(&[FIREWALLD]);
        let ops = plan(
            &sandbox,
            config(serde_json::json!({
                "allow": ["8080/tcp", "53/udp"], "remove": 22, "allow_service": "http"
            })),
        )
        .unwrap();
        let actions: Vec<String> = ops
            .iter()
            .map(|op| match op {
                Op::FirewallAdapter { backend, action } => {
                    format!("{backend} {}", action["action"].as_str().unwrap())
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            actions,
            [
                "firewalld allow_port",
                "firewalld allow_port",
                "firewalld remove_port",
                "firewalld allow_service"
            ]
        );
        // A bare port number means tcp.
        let Op::FirewallAdapter { action, .. } = &ops[2] else {
            unreachable!()
        };
        assert_eq!(action["port"], 22);
        assert_eq!(action["proto"], "tcp");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bad_input_is_refused_with_the_field_named() {
        let (root, sandbox) = tree(&[FIREWALLD]);
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"allow": "0"}),
            serde_json::json!({"allow": "70000/tcp"}),
            serde_json::json!({"allow": "22/sctp"}),
            serde_json::json!({"allow": "ssh"}),
            serde_json::json!({"allow_service": "--reload"}),
        ] {
            assert!(plan(&sandbox, config(bad.clone())).is_err(), "{bad}");
        }
        let unknown: Result<Config, _> = serde_json::from_value(serde_json::json!({"zone": "x"}));
        assert!(unknown.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ufw_takes_ports_but_not_services() {
        let (root, sandbox) = tree(&[
            ("/usr/sbin/ufw", ""),
            ("/etc/ufw/ufw.conf", "ENABLED=yes\n"),
        ]);
        let ops = plan(&sandbox, config(serde_json::json!({"allow": "22"}))).unwrap();
        assert!(matches!(&ops[0], Op::FirewallAdapter { backend, .. } if backend == "ufw"));
        assert!(
            plan(
                &sandbox,
                config(serde_json::json!({"allow_service": "http"}))
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_manager_that_is_not_running_is_reported_not_bypassed() {
        let (root, sandbox) = tree(&[("/usr/bin/firewall-cmd", "")]);
        let error = plan(&sandbox, config(serde_json::json!({"allow": "22"}))).unwrap_err();
        assert!(error.to_string().contains("not running"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_a_manager_basic_protection_needs_a_deliberate_yes() {
        let (root, sandbox) = tree(&[]);
        assert!(plan(&sandbox, config(serde_json::json!({"allow": "22"}))).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn basic_protection_keeps_what_is_listening_and_ends_in_a_drop() {
        let tcp = format!(
            "{HEADER}   0: 00000000:0016 00000000:0000 0A 0\n   1: 0100007F:0CEA 00000000:0000 0A 0\n"
        );
        let (root, sandbox) = tree(&[("/proc/net/tcp", &tcp)]);
        let ops = plan(
            &sandbox,
            config(serde_json::json!({"enable_basic": true, "allow": "443"})),
        )
        .unwrap();
        let Op::FileWrite { path, content, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(path, names::ARTIFACT_FIREWALL_SETTINGS);
        let settings: Settings = serde_json::from_str(content).unwrap();
        // sshd (22) because it is listening on every address; the loopback
        // service on 3306 is not exposed so it is not opened.
        assert_eq!(
            settings.ports,
            [
                PortRule {
                    port: 22,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 443,
                    proto: Proto::Tcp
                }
            ]
        );
        let Op::NftFragment { fragment } = &ops[1] else {
            panic!()
        };
        let fragment: Fragment = serde_json::from_value(fragment.clone()).unwrap();
        fragment.validate().unwrap();
        let chain = &fragment.chains[0];
        assert_eq!(chain.name, "net_firewall_input");
        assert_eq!(chain.hook, Hook::Input);
        assert_eq!(chain.priority, 5);
        assert!(chain.rules[0].ct_established);
        assert!(chain.rules[1].iif_loopback);
        assert!(chain.rules[2].icmp);
        assert!(
            chain
                .rules
                .iter()
                .any(|r| r.iif_prefix.as_deref() == Some("docker"))
        );
        assert!(
            chain
                .rules
                .iter()
                .any(|r| r.iif_prefix.as_deref() == Some("virbr"))
        );
        assert_eq!(chain.rules.last().unwrap().verdict, Verdict::Drop);
        assert!(chain.rules.last().unwrap().dports.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn later_plans_edit_the_remembered_ports() {
        let saved =
            r#"{"ports":[{"port":22,"proto":"tcp"},{"port":8080,"proto":"tcp"}],"mdns":true}"#;
        let (root, sandbox) = tree(&[(names::ARTIFACT_FIREWALL_SETTINGS, saved)]);
        let ops = plan(
            &sandbox,
            config(serde_json::json!({"remove": "8080", "allow": "53/udp"})),
        )
        .unwrap();
        let Op::FileWrite { content, .. } = &ops[0] else {
            panic!()
        };
        let settings: Settings = serde_json::from_str(content).unwrap();
        assert_eq!(
            settings.ports,
            [
                PortRule {
                    port: 22,
                    proto: Proto::Tcp
                },
                PortRule {
                    port: 53,
                    proto: Proto::Udp
                }
            ]
        );
        assert!(settings.mdns, "mdns stays as it was");
        // A remembered file means no enable_basic is needed, and listening
        // ports are not re-added.
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn many_ports_are_split_into_rules_of_sixteen() {
        let settings = Settings {
            ports: (1000..1040)
                .map(|port| PortRule {
                    port,
                    proto: Proto::Tcp,
                })
                .collect(),
            mdns: false,
        };
        let fragment = basic_chain(&settings);
        fragment.validate().unwrap();
        let tcp_rules = fragment.chains[0]
            .rules
            .iter()
            .filter(|r| !r.dports.is_empty() && r.protocols == [ibexwall_sys::nft::Proto::Tcp])
            .count();
        assert_eq!(tcp_rules, 3);
    }

    #[test]
    fn services_are_not_available_in_basic_mode() {
        let (root, sandbox) = tree(&[]);
        let error = plan(
            &sandbox,
            config(serde_json::json!({"enable_basic": true, "allow_service": "ssh"})),
        )
        .unwrap_err();
        assert!(error.to_string().contains("firewalld"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verify_reads_the_managers_own_files() {
        let zone = r#"<zone><service name="http"/><port protocol="tcp" port="8080"/></zone>"#;
        let (root, sandbox) = tree(&[FIREWALLD, ("/etc/firewalld/zones/public.xml", zone)]);
        let op = |action: serde_json::Value| Op::FirewallAdapter {
            backend: "firewalld".into(),
            action,
        };
        assert!(verify(
            &sandbox,
            &[
                op(serde_json::json!({"action": "allow_port", "port": 8080, "proto": "tcp"})),
                op(serde_json::json!({"action": "allow_service", "name": "http"})),
                op(serde_json::json!({"action": "remove_port", "port": 22, "proto": "tcp"})),
            ]
        ));
        assert!(!verify(
            &sandbox,
            &[op(
                serde_json::json!({"action": "allow_port", "port": 9, "proto": "tcp"})
            )]
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_profile_becomes_the_firewalld_default_zone_when_the_zone_exists() {
        let (root, sandbox) = tree(&[
            FIREWALLD,
            ("/usr/bin/firewall-cmd", ""),
            ("/usr/lib/firewalld/zones/home.xml", "<zone/>"),
            ("/usr/lib/firewalld/zones/drop.xml", "<zone/>"),
        ]);
        let ops = plan(&sandbox, config(serde_json::json!({"profile": "home"}))).unwrap();
        let Op::FirewallAdapter { action, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(action["action"], "set_default_zone");
        assert_eq!(action["name"], "home");
        // travel is the drop zone.
        let ops = plan(&sandbox, config(serde_json::json!({"profile": "travel"}))).unwrap();
        let Op::FirewallAdapter { action, .. } = &ops[0] else {
            panic!()
        };
        assert_eq!(action["name"], "drop");
        // A zone this firewalld does not ship is refused, not guessed.
        let error = plan(&sandbox, config(serde_json::json!({"profile": "work"}))).unwrap_err();
        assert!(error.to_string().contains("no `work` zone"), "{error}");
        assert!(plan(&sandbox, config(serde_json::json!({"profile": "cafe"}))).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profiles_are_only_for_firewalld() {
        let (root, sandbox) = tree(&[
            ("/usr/sbin/ufw", ""),
            ("/etc/ufw/ufw.conf", "ENABLED=yes\n"),
        ]);
        assert!(plan(&sandbox, config(serde_json::json!({"profile": "home"}))).is_err());
        std::fs::remove_dir_all(root).unwrap();
        let (root, sandbox) = tree(&[]);
        assert!(
            plan(
                &sandbox,
                config(serde_json::json!({"enable_basic": true, "profile": "home"}))
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
