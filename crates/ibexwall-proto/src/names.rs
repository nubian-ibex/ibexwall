// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Canonical names, paths and identifiers.
//!
//! Every identifier from the naming spec lives here; never sprinkle these
//! as literals around the codebase. Path helpers honor `IBEXWALL_ROOT`,
//! the unprivileged sandbox prefix used in development and tests.

use std::path::{Path, PathBuf};

pub const PRODUCT_NAME: &str = "IbexWall";
pub const TAGLINE: &str = "Security Center for Linux";
pub const ORG_GITHUB: &str = "nubian-ibex";
/// Depends on acquiring ibexwall.com (pending P-01); keep centralized here.
pub const REVERSE_DNS: &str = "com.ibexwall";

// Binaries (also used as journald SYSLOG_IDENTIFIER values).
pub const BIN_DAEMON: &str = "ibexwalld";
pub const BIN_CLI: &str = "ibexctl";
pub const BIN_AGENT: &str = "ibexwall-agent";
pub const BIN_DNS: &str = "ibexwall-dns";
/// The eBPF connect monitor; it feeds the core over `monitor_socket()`.
pub const BIN_EBPF_LOADER: &str = "ibexwall-ebpf-loader";
/// systemd unit that runs the loader with only the capabilities it needs.
pub const UNIT_MONITOR: &str = "ibexwall-monitor.service";
/// Records that the person chose whether the monitor runs, so the package
/// scripts turn it on at the first install only, never against a choice.
pub const MONITOR_CHOICE: &str = "/var/lib/ibexwall/monitor.choice";
pub const BIN_MCP: &str = "ibexwall-mcp";
pub const BIN_WEB: &str = "ibexwall-web";
pub const PLUGIN_BIN_PREFIX: &str = "ibexwall-plugin-";

// systemd units.
pub const UNIT_DAEMON: &str = "ibexwalld.service";
pub const UNIT_DAEMON_SOCKET: &str = "ibexwalld.socket";
pub const UNIT_AGENT: &str = "ibexwall-agent.service";

/// Unit name for a plugin instance (`ibexwall-plugin@<id>.service`).
pub fn plugin_unit(id: &str) -> String {
    format!("ibexwall-plugin@{id}.service")
}

// System users and groups.
pub const SYSTEM_GROUP: &str = "ibexwall";
pub const DNS_USER: &str = "ibexwall-dns";

// Directory suffixes; combine with [`root`] to get absolute paths.
pub const CONFIG_DIR: &str = "/etc/ibexwall";
pub const STATE_DIR: &str = "/var/lib/ibexwall";
/// The resolver's own state (its block lists), apart from the daemon's:
/// the daemon's directory is root's and closed to the resolver's user.
pub const DNS_STATE_DIR: &str = "/var/lib/ibexwall-dns";
pub const RUNTIME_DIR: &str = "/run/ibexwall";
pub const PLUGIN_INSTALL_DIR: &str = "/usr/lib/ibexwall/plugins";
pub const LOCAL_PLUGIN_DIR: &str = "/etc/ibexwall/plugins.local";
/// Shipped compliance profiles (read-only), and operator overrides.
pub const PROFILE_INSTALL_DIR: &str = "/usr/lib/ibexwall/profiles";
pub const PROFILE_CONFIG_DIR: &str = "/etc/ibexwall/profiles";

// Environment variables.
pub const ENV_ROOT: &str = "IBEXWALL_ROOT";
pub const ENV_LOG: &str = "IBEXWALL_LOG";

/// Sandbox root for development and tests (`IBEXWALL_ROOT`), `/` otherwise.
pub fn root() -> PathBuf {
    match std::env::var_os(ENV_ROOT) {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/"),
    }
}

/// Joins an absolute path suffix under `base` (leading slashes stripped).
/// Pure helper so path composition can be tested without touching the
/// environment.
pub fn path_under(base: &Path, suffix: &str) -> PathBuf {
    base.join(suffix.trim_start_matches('/'))
}

pub fn config_dir() -> PathBuf {
    path_under(&root(), CONFIG_DIR)
}
pub fn state_dir() -> PathBuf {
    path_under(&root(), STATE_DIR)
}
pub fn runtime_dir() -> PathBuf {
    path_under(&root(), RUNTIME_DIR)
}
pub fn plugin_install_dir() -> PathBuf {
    path_under(&root(), PLUGIN_INSTALL_DIR)
}
pub fn local_plugin_dir() -> PathBuf {
    path_under(&root(), LOCAL_PLUGIN_DIR)
}
pub fn profile_install_dir() -> PathBuf {
    path_under(&root(), PROFILE_INSTALL_DIR)
}
pub fn profile_config_dir() -> PathBuf {
    path_under(&root(), PROFILE_CONFIG_DIR)
}

/// Where the resolver publishes its counters (refreshed while running).
pub fn dns_status_file() -> PathBuf {
    runtime_dir().join("dns").join("status.json")
}

/// Datagram socket the core binds for the resolver's answers (name, ip,
/// ttl), so the monitor can name a connection's destination. It lives in
/// the core's runtime directory, which the core may write (the resolver's
/// own directory is closed to it), and is open to the resolver's group.
pub fn dns_answers_socket() -> PathBuf {
    runtime_dir().join("answers.sock")
}

/// Stream socket the core binds for the connection monitor (root only).
pub fn monitor_socket() -> PathBuf {
    runtime_dir().join("monitor.sock")
}

pub fn core_socket() -> PathBuf {
    runtime_dir().join("core.sock")
}
/// Socket of a plugin supervisor (`/run/ibexwall/plugins/<id>.sock`).
pub fn plugin_socket(id: &str) -> PathBuf {
    runtime_dir().join("plugins").join(format!("{id}.sock"))
}
pub fn state_db() -> PathBuf {
    state_dir().join("state.db")
}
pub fn snapshots_dir() -> PathBuf {
    state_dir().join("snapshots")
}
pub fn blocklists_dir() -> PathBuf {
    path_under(&root(), DNS_STATE_DIR).join("blocklists")
}
pub fn trust_dir() -> PathBuf {
    config_dir().join("trust")
}
pub fn mcp_config() -> PathBuf {
    config_dir().join("mcp.toml")
}

// Generated artifacts. They must always carry the product name (project
// rule: only own artifacts, never the distro's files).
pub const ARTIFACT_SYSCTL: &str = "/etc/sysctl.d/90-ibexwall.conf";
pub const ARTIFACT_RESOLVED: &str = "/etc/systemd/resolved.conf.d/50-ibexwall.conf";
pub const ARTIFACT_NM_DNS: &str = "/etc/NetworkManager/conf.d/50-ibexwall-dns.conf";
/// The secure DNS resolver's settings file, written by `net.dns` and read
/// by `ibexwall-dns` (canonical path; the engine translates under a
/// sandbox root).
pub const ARTIFACT_DNS_SETTINGS: &str = "/etc/ibexwall/dns/resolver.json";
/// The inbound rules `net.firewall` keeps when it owns the firewall itself
/// (no firewalld or ufw): the ports it allows.
pub const ARTIFACT_FIREWALL_SETTINGS: &str = "/etc/ibexwall/firewall/inbound.json";

/// Every system artifact path IbexWall is allowed to create.
pub fn artifact_paths() -> [&'static str; 5] {
    [
        ARTIFACT_SYSCTL,
        ARTIFACT_RESOLVED,
        ARTIFACT_NM_DNS,
        ARTIFACT_DNS_SETTINGS,
        ARTIFACT_FIREWALL_SETTINGS,
    ]
}

// nftables.
pub const NFT_TABLE: &str = "ibexwall";
/// The secure DNS enforcement chain (prefix `net_dns` per the plugin id).
pub const DNS_NFT_CHAIN: &str = "net_dns_guard";
/// The basic inbound protection chain (prefix `net_firewall`).
pub const FIREWALL_NFT_CHAIN: &str = "net_firewall_input";

// Local DNS resolver defaults (configurable).
pub const DNS_BIND_ADDR: &str = "127.0.0.153";
pub const DNS_BIND_PORT: u16 = 53;

// varlink interfaces.
pub const IFACE_CORE: &str = "com.ibexwall.Core";
pub const IFACE_PLUGIN: &str = "com.ibexwall.Plugin";
pub const IFACE_POLICY: &str = "com.ibexwall.Policy";

// polkit actions.
pub const POLKIT_READ: &str = "com.ibexwall.read";
pub const POLKIT_PLAN: &str = "com.ibexwall.plan";
pub const POLKIT_APPLY: &str = "com.ibexwall.apply";
pub const POLKIT_ROLLBACK: &str = "com.ibexwall.rollback";
pub const POLKIT_APPS_DECIDE: &str = "com.ibexwall.apps.decide";
pub const POLKIT_PLUGINS_MANAGE: &str = "com.ibexwall.plugins.manage";
pub const POLKIT_PROPOSALS_CREATE: &str = "com.ibexwall.proposals.create";
pub const POLKIT_PROPOSALS_DECIDE: &str = "com.ibexwall.proposals.decide";
pub const POLKIT_POLICY_PROVIDER: &str = "com.ibexwall.policy.provider";
pub const POLKIT_EXPORT: &str = "com.ibexwall.export";

/// All polkit actions shipped by the daemon.
pub fn polkit_actions() -> [&'static str; 10] {
    [
        POLKIT_READ,
        POLKIT_PLAN,
        POLKIT_APPLY,
        POLKIT_ROLLBACK,
        POLKIT_APPS_DECIDE,
        POLKIT_PLUGINS_MANAGE,
        POLKIT_PROPOSALS_CREATE,
        POLKIT_PROPOSALS_DECIDE,
        POLKIT_POLICY_PROVIDER,
        POLKIT_EXPORT,
    ]
}

// Locales (source locale plus shipped translations). A language is added
// here and with its files; see docs/translating.md.
pub const LOCALE_SOURCE: &str = "en";
pub const LOCALES: [&str; 5] = ["en", "pt-BR", "es", "fr", "de"];

// Structured journal fields.
pub const JOURNAL_PLUGIN_FIELD: &str = "IBEXWALL_PLUGIN";
pub const JOURNAL_TX_FIELD: &str = "IBEXWALL_TX";

// Domains.
pub const DOMAIN_MAIN: &str = "ibexwall.com";
pub const DOMAIN_DOCS: &str = "docs.ibexwall.com";
pub const DOMAIN_PKGS: &str = "pkgs.ibexwall.com";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_artifacts_carry_the_product_name() {
        for path in artifact_paths() {
            assert!(
                path.contains(NFT_TABLE),
                "artifact `{path}` must contain `{NFT_TABLE}`"
            );
        }
    }

    #[test]
    fn plugin_unit_uses_the_template() {
        assert_eq!(plugin_unit("net.dns"), "ibexwall-plugin@net.dns.service");
    }

    #[test]
    fn path_under_strips_leading_slashes() {
        let base = Path::new("/tmp/ibexwall-root");
        assert_eq!(path_under(base, "/etc/ibexwall"), base.join("etc/ibexwall"));
        assert_eq!(path_under(base, "etc/ibexwall"), base.join("etc/ibexwall"));
    }

    #[test]
    fn polkit_actions_use_the_reverse_dns_prefix() {
        for action in polkit_actions() {
            assert!(
                action.starts_with(REVERSE_DNS),
                "action `{action}` must be under {REVERSE_DNS}"
            );
        }
    }
}
