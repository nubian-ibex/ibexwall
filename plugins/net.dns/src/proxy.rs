// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A local proxy that already encrypts this machine's DNS (dnscrypt-proxy).
//! It is read from its configuration and from systemd's record of running
//! units; nothing is changed. When the system resolver sends its lookups
//! through such a proxy, they already leave the computer encrypted, so
//! IbexWall leaves the setup alone instead of putting its own resolver in
//! the way.

use std::net::IpAddr;

use ibexwall_sdk::Sandbox;

const CONFIGS: [&str; 2] = [
    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
    "/etc/dnscrypt-proxy.toml",
];

/// What the proxy is set to do, as far as its configuration says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub name: &'static str,
    /// The addresses it listens on, as written (`127.0.0.1:53`).
    pub listen: Vec<String>,
    /// The resolvers it is limited to; empty means it picks by itself.
    pub servers: Vec<String>,
    pub dnssec: Option<bool>,
    pub no_log: Option<bool>,
    pub no_filter: Option<bool>,
    /// Whether the system resolver sends its lookups to it.
    pub in_use: bool,
}

fn running(sandbox: &Sandbox) -> bool {
    // systemd leaves one of these for every unit it started; the proxy is
    // often started by its socket on Debian, Ubuntu and Arch.
    ["service", "socket"].iter().any(|kind| {
        sandbox.has_entry(&format!(
            "/run/systemd/units/invocation:dnscrypt-proxy.{kind}"
        ))
    })
}

fn strings(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The addresses systemd listens on for the proxy, where it is started by
/// its socket (Debian, Ubuntu and Arch ship it that way: the proxy itself then
/// has no right to bind port 53). Drop-ins come last and an empty value
/// clears what came before, as in systemd.
fn socket_addresses(sandbox: &Sandbox) -> Vec<String> {
    let mut texts: Vec<String> = [
        "/usr/lib/systemd/system/dnscrypt-proxy.socket",
        "/etc/systemd/system/dnscrypt-proxy.socket",
    ]
    .iter()
    .filter_map(|path| sandbox.read(path))
    .collect();
    let mut dropins = sandbox.list("/etc/systemd/system/dnscrypt-proxy.socket.d");
    dropins.sort();
    for name in dropins.into_iter().filter(|n| n.ends_with(".conf")) {
        if let Some(text) = sandbox.read(&format!(
            "/etc/systemd/system/dnscrypt-proxy.socket.d/{name}"
        )) {
            texts.push(text);
        }
    }
    let mut out: Vec<String> = Vec::new();
    for line in texts.iter().flat_map(|t| t.lines()).map(str::trim) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !matches!(key.trim(), "ListenStream" | "ListenDatagram") {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            out.clear();
        } else if value.parse::<std::net::SocketAddr>().is_ok() && !out.iter().any(|a| a == value) {
            out.push(value.to_string());
        }
    }
    out
}

/// The addresses the system resolver forwards to, loopback included, in the
/// files that list them.
fn system_servers(sandbox: &Sandbox) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for path in [
        "/run/systemd/resolve/resolv.conf",
        "/run/NetworkManager/resolv.conf",
        "/etc/resolv.conf",
    ] {
        for line in sandbox.read(path).unwrap_or_default().lines() {
            if let Some(rest) = line.trim().strip_prefix("nameserver")
                && let Ok(ip) = rest.trim().parse::<IpAddr>()
            {
                out.push(ip);
            }
        }
    }
    out
}

fn host_of(listen: &str) -> Option<(IpAddr, u16)> {
    let socket: std::net::SocketAddr = listen.parse().ok()?;
    Some((socket.ip(), socket.port()))
}

/// The proxy, when it is installed, configured and running.
pub fn local_encrypting_proxy(sandbox: &Sandbox) -> Option<Proxy> {
    if !running(sandbox) {
        return None;
    }
    let text = CONFIGS.iter().find_map(|path| sandbox.read(path))?;
    let table: toml::Table = text.parse().ok()?;
    let mut listen = strings(&table, "listen_addresses");
    for address in socket_addresses(sandbox) {
        if !listen.contains(&address) {
            listen.push(address);
        }
    }
    let flag = |key: &str| table.get(key).and_then(toml::Value::as_bool);
    // Only a loopback address on the DNS port can be the system's resolver:
    // another port is a second listener the system does not use.
    let local: Vec<IpAddr> = listen
        .iter()
        .filter_map(|l| host_of(l))
        .filter(|(ip, port)| *port == 53 && ip.is_loopback())
        .map(|(ip, _)| ip)
        .collect();
    let system = system_servers(sandbox);
    let in_use = system.iter().any(|ip| local.contains(ip));
    Some(Proxy {
        name: "dnscrypt-proxy",
        listen,
        servers: strings(&table, "server_names"),
        dnssec: flag("require_dnssec"),
        no_log: flag("require_nolog"),
        no_filter: flag("require_nofilter"),
        in_use,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "server_names = ['quad9-doh', 'cloudflare']\n\
        listen_addresses = ['127.0.0.1:53', '[::1]:53']\n\
        require_dnssec = true\nrequire_nolog = true\nrequire_nofilter = false\n";

    fn machine(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, text) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, text).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    #[test]
    fn a_running_proxy_that_the_system_resolver_uses_is_in_use() {
        let (root, sandbox) = machine(
            "use",
            &[
                ("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", CONFIG),
                ("/run/systemd/units/invocation:dnscrypt-proxy.socket", ""),
                ("/run/systemd/resolve/resolv.conf", "nameserver 127.0.0.1\n"),
            ],
        );
        let proxy = local_encrypting_proxy(&sandbox).unwrap();
        assert!(proxy.in_use);
        assert_eq!(proxy.servers, ["quad9-doh", "cloudflare"]);
        assert_eq!(proxy.dnssec, Some(true));
        assert_eq!(proxy.no_filter, Some(false));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_proxy_the_system_does_not_ask_is_running_but_not_in_use() {
        let (root, sandbox) = machine(
            "idle",
            &[
                ("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", CONFIG),
                ("/run/systemd/units/invocation:dnscrypt-proxy.service", ""),
                (
                    "/run/systemd/resolve/resolv.conf",
                    "nameserver 192.168.1.1\n",
                ),
            ],
        );
        assert!(!local_encrypting_proxy(&sandbox).unwrap().in_use);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_proxy_started_by_its_socket_listens_where_the_socket_says() {
        let (root, sandbox) = machine(
            "socket",
            &[
                (
                    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
                    "listen_addresses = []\n",
                ),
                (
                    "/usr/lib/systemd/system/dnscrypt-proxy.socket",
                    "[Socket]\nListenStream=127.0.2.1:53\nListenDatagram=127.0.2.1:53\n",
                ),
                ("/run/systemd/units/invocation:dnscrypt-proxy.socket", ""),
                ("/run/systemd/resolve/resolv.conf", "nameserver 127.0.2.1\n"),
            ],
        );
        let proxy = local_encrypting_proxy(&sandbox).unwrap();
        assert_eq!(proxy.listen, ["127.0.2.1:53"]);
        assert!(proxy.in_use);
        std::fs::remove_dir_all(root).unwrap();
        // A drop-in that empties the list and names another address wins.
        let (root, sandbox) = machine(
            "dropin",
            &[
                ("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", ""),
                (
                    "/usr/lib/systemd/system/dnscrypt-proxy.socket",
                    "[Socket]\nListenStream=127.0.2.1:53\n",
                ),
                (
                    "/etc/systemd/system/dnscrypt-proxy.socket.d/override.conf",
                    "[Socket]\nListenStream=\nListenStream=127.0.0.1:53\n",
                ),
                ("/run/systemd/units/invocation:dnscrypt-proxy.socket", ""),
                ("/run/systemd/resolve/resolv.conf", "nameserver 127.0.0.1\n"),
            ],
        );
        let proxy = local_encrypting_proxy(&sandbox).unwrap();
        assert_eq!(proxy.listen, ["127.0.0.1:53"]);
        assert!(proxy.in_use);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stopped_proxy_or_one_on_another_port_is_not_the_resolver() {
        let (root, stopped) = machine(
            "stopped",
            &[("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", CONFIG)],
        );
        assert!(local_encrypting_proxy(&stopped).is_none());
        let (root2, other) = machine(
            "port",
            &[
                (
                    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
                    "listen_addresses = ['127.0.0.1:5353']\n",
                ),
                ("/run/systemd/units/invocation:dnscrypt-proxy.service", ""),
                ("/etc/resolv.conf", "nameserver 127.0.0.1\n"),
            ],
        );
        assert!(!local_encrypting_proxy(&other).unwrap().in_use);
        for r in [root, root2] {
            std::fs::remove_dir_all(r).unwrap();
        }
    }

    #[test]
    fn an_unreadable_configuration_is_not_guessed_at() {
        let (root, sandbox) = machine(
            "bad",
            &[
                ("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", "listen = [[[\n"),
                ("/run/systemd/units/invocation:dnscrypt-proxy.service", ""),
            ],
        );
        assert!(local_encrypting_proxy(&sandbox).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
