// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser for `/proc/net/{tcp,tcp6,udp,udp6}` and best-effort mapping of
//! socket inodes to process names.

use std::collections::BTreeMap;

use ibexwall_sdk::Sandbox;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub proto: Proto,
    pub port: u16,
    pub inode: u64,
}

/// TCP LISTEN.
const TCP_LISTEN: &str = "0A";
/// An unconnected UDP socket shows as TCP_CLOSE.
const UDP_UNCONNECTED: &str = "07";

/// Parses one table. Lines that do not parse are skipped: `/proc` content
/// is untrusted input for a parser, never a reason to fail.
pub fn parse_table(text: &str, proto: Proto, ipv6: bool) -> Vec<Socket> {
    let wanted_state = match proto {
        Proto::Tcp => TCP_LISTEN,
        Proto::Udp => UDP_UNCONNECTED,
    };
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...
        if fields.len() < 10 || fields[3] != wanted_state {
            continue;
        }
        let Some((addr, port)) = fields[1].split_once(':') else {
            continue;
        };
        if !is_wildcard(addr, ipv6) {
            continue;
        }
        let (Ok(port), Ok(inode)) = (u16::from_str_radix(port, 16), fields[9].parse::<u64>())
        else {
            continue;
        };
        if port == 0 {
            continue;
        }
        sockets.push(Socket { proto, port, inode });
    }
    sockets
}

/// `0.0.0.0` or `::`: reachable on every interface.
fn is_wildcard(addr: &str, ipv6: bool) -> bool {
    let expected = if ipv6 { 32 } else { 8 };
    addr.len() == expected && addr.bytes().all(|b| b == b'0')
}

pub fn exposed_sockets(sandbox: &Sandbox) -> Vec<Socket> {
    let mut all = Vec::new();
    for (file, proto, ipv6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
    ] {
        if let Some(text) = sandbox.read(file) {
            all.extend(parse_table(&text, proto, ipv6));
        }
    }
    all
}

/// Best-effort inode to process name. Needs permission to read other
/// processes' fd directories; sockets that cannot be resolved are simply
/// absent from the map.
pub fn process_names(sandbox: &Sandbox, sockets: &[Socket]) -> BTreeMap<u64, String> {
    let wanted: std::collections::BTreeSet<u64> = sockets.iter().map(|s| s.inode).collect();
    let mut names = BTreeMap::new();
    if wanted.is_empty() {
        return names;
    }
    for pid in sandbox.list("/proc") {
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        for fd in sandbox.list(&format!("/proc/{pid}/fd")) {
            let Some(target) = sandbox.read_link(&format!("/proc/{pid}/fd/{fd}")) else {
                continue;
            };
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u64>().ok())
            else {
                continue;
            };
            if wanted.contains(&inode)
                && let Some(comm) = sandbox.read(&format!("/proc/{pid}/comm"))
            {
                names.insert(inode, sanitize(comm.trim()));
            }
        }
    }
    names
}

/// Process names are chosen by the process itself: drop control
/// characters and bound the length before they travel anywhere.
fn sanitize(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_only_listening_wildcards() {
        let text = "header\n\
            0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 100 1 x\n\
            1: 0100007F:0035 00000000:0000 0A 0:0 0:0 0 0 0 101 1 x\n\
            2: 00000000:01BB 0A00000A:D2F4 01 0:0 0:0 0 0 0 102 1 x\n";
        let sockets = parse_table(text, Proto::Tcp, false);
        assert_eq!(
            sockets,
            vec![Socket {
                proto: Proto::Tcp,
                port: 22,
                inode: 100
            }]
        );
    }

    #[test]
    fn ipv6_wildcard_needs_a_full_zero_address() {
        let wildcard = "h\n0: 00000000000000000000000000000000:0050 0:0 0A 0:0 0:0 0 0 0 7 1\n";
        assert_eq!(parse_table(wildcard, Proto::Tcp, true).len(), 1);
        let loopback = "h\n0: 00000000000000000000000001000000:0050 0:0 0A 0:0 0:0 0 0 0 7 1\n";
        assert!(parse_table(loopback, Proto::Tcp, true).is_empty());
    }

    #[test]
    fn sanitizes_hostile_process_names() {
        assert_eq!(sanitize("ssh\x1b[31md\nname"), "ssh[31mdname");
        assert_eq!(sanitize(&"x".repeat(500)).len(), 64);
    }

    proptest! {
        #[test]
        fn the_parser_never_panics_on_arbitrary_input(text in ".{0,400}") {
            let _ = parse_table(&text, Proto::Tcp, false);
            let _ = parse_table(&text, Proto::Udp, true);
        }
    }
}
