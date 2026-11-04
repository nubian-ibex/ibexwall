// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Redaction before an answer leaves the server (spec 4.12): a user name, the
//! host name, an SSID, a MAC address and a private IP become a stable
//! pseudonym (an HMAC of the value under a salt that never leaves this
//! machine), and home folders become `~`. The same value always gets the same
//! pseudonym, so an assistant can still say "the same device" without
//! learning which one it is. One choke point applies it to a whole answer
//! tree: no tool formats its own output around it.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[derive(Debug, Clone)]
pub struct Redactor {
    salt: Vec<u8>,
    users: BTreeSet<String>,
    hosts: BTreeSet<String>,
    kinds: BTreeSet<String>,
}

fn is_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_')
}

fn is_mac(token: &str) -> bool {
    let parts: Vec<&str> = token.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

fn private_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

impl Redactor {
    pub fn new(salt: Vec<u8>, users: &[String], hosts: &[String], kinds: &[String]) -> Self {
        Self {
            salt,
            // Names too short to be told apart from words are left alone, and
            // root is a role, not a person.
            users: users
                .iter()
                .filter(|u| u.len() >= 3 && *u != "root")
                .cloned()
                .collect(),
            hosts: hosts.iter().filter(|h| h.len() >= 2).cloned().collect(),
            kinds: kinds.iter().cloned().collect(),
        }
    }

    fn on(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }

    /// `kind-1a2b3c4d`: stable for this salt, meaningless without it.
    pub fn pseudonym(&self, kind: &str, value: &str) -> String {
        let mac = hmac_sha256(&self.salt, format!("{kind}\0{value}").as_bytes());
        format!("{kind}-{}", hex::encode(&mac[..4]))
    }

    /// An SSID, wherever a tool knows it is one.
    pub fn ssid(&self, value: &str) -> String {
        if self.on("ssid") {
            self.pseudonym("ssid", value)
        } else {
            value.to_string()
        }
    }

    fn token(&self, token: &str) -> Option<String> {
        if self.on("mac") && is_mac(token) {
            return Some(self.pseudonym("mac", &token.to_ascii_lowercase().replace('-', ":")));
        }
        if self.on("private_ip") {
            if let Ok(ip) = token.parse::<Ipv4Addr>()
                && private_v4(ip)
            {
                return Some(self.pseudonym("ip", token));
            }
            if token.contains(':')
                && let Ok(ip) = token.parse::<Ipv6Addr>()
                && private_v6(ip)
            {
                return Some(self.pseudonym("ip", &ip.to_string()));
            }
        }
        if self.on("username") && self.users.contains(token) {
            return Some(self.pseudonym("user", token));
        }
        if self.on("hostname") {
            let short = token.split('.').next().unwrap_or(token);
            if self.hosts.contains(token) || (token.contains('.') && self.hosts.contains(short)) {
                return Some(self.pseudonym("host", short));
            }
            if self.hosts.contains(short) && token == short {
                return Some(self.pseudonym("host", short));
            }
        }
        None
    }

    /// Redacts free text.
    pub fn text(&self, text: &str) -> String {
        let text = if self.on("home_path") {
            self.homes(text)
        } else {
            text.to_string()
        };
        let mut out = String::with_capacity(text.len());
        let mut chars = text.char_indices().peekable();
        while let Some((start, c)) = chars.next() {
            if !is_token(c) {
                out.push(c);
                continue;
            }
            let mut end = start + c.len_utf8();
            while let Some(&(i, n)) = chars.peek() {
                if is_token(n) {
                    end = i + n.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            let word = &text[start..end];
            // Sentence punctuation stuck to a token is not part of it.
            let trimmed = word.trim_end_matches(['.', ':', '-']);
            let tail = &word[trimmed.len()..];
            match self.token(trimmed) {
                Some(pseudo) => {
                    out.push_str(&pseudo);
                    out.push_str(tail);
                }
                None => out.push_str(word),
            }
        }
        out
    }

    /// `/home/<name>/x` becomes `~/x`, `/root/x` too.
    fn homes(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find("/home/").or_else(|| rest.find("/root")) {
            out.push_str(&rest[..at]);
            let after = &rest[at..];
            if let Some(tail) = after.strip_prefix("/home/") {
                let name_len = tail
                    .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
                    .unwrap_or(tail.len());
                out.push('~');
                rest = &tail[name_len..];
            } else if after.starts_with("/root")
                && after[5..]
                    .chars()
                    .next()
                    .is_none_or(|c| c == '/' || !c.is_ascii_alphanumeric())
            {
                out.push('~');
                rest = &after[5..];
            } else {
                out.push_str("/root");
                rest = &after[5..];
            }
        }
        out.push_str(rest);
        out
    }

    /// Every string in a JSON tree (keys are ours and stay as they are).
    pub fn value(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.value(v)),
            Value::Object(map) => {
                for (key, v) in map.iter_mut() {
                    // A field that is an SSID by name, whatever it holds.
                    if key == "ssid"
                        && let Value::String(s) = v
                    {
                        *s = self.ssid(s);
                    } else {
                        self.value(v);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn redactor() -> Redactor {
        Redactor::new(
            b"a local salt".to_vec(),
            &["ana".into(), "bruno".into(), "root".into(), "al".into()],
            &["thinkpad-ana".into()],
            &[
                "username",
                "hostname",
                "ssid",
                "mac",
                "private_ip",
                "home_path",
            ]
            .map(String::from),
        )
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vector() {
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn identifying_values_become_stable_pseudonyms() {
        let r = redactor();
        let once = r.text("ana joined from 192.168.1.20 with aa:bb:cc:dd:ee:ff on thinkpad-ana");
        assert!(!once.contains("ana joined"));
        for leaked in ["192.168.1.20", "aa:bb:cc:dd:ee:ff", "thinkpad-ana"] {
            assert!(!once.contains(leaked), "{once}");
        }
        assert!(
            once.contains("user-")
                && once.contains("ip-")
                && once.contains("mac-")
                && once.contains("host-")
        );
        // The same value, the same pseudonym; a different value, a different one.
        assert_eq!(
            r.text("192.168.1.20"),
            r.text("seen 192.168.1.20.")
                .trim_start_matches("seen ")
                .trim_end_matches('.')
        );
        assert_ne!(r.text("192.168.1.20"), r.text("192.168.1.21"));
        // A different salt gives different pseudonyms (nothing to correlate across machines).
        let other = Redactor::new(
            b"another".to_vec(),
            &["ana".into()],
            &[],
            &["username".to_string()],
        );
        assert_ne!(other.text("ana"), r.text("ana"));
    }

    #[test]
    fn mac_case_and_separator_do_not_change_the_pseudonym() {
        let r = redactor();
        assert_eq!(r.text("AA-BB-CC-DD-EE-FF"), r.text("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn public_addresses_roles_and_ordinary_words_are_left_alone() {
        let r = redactor();
        let text = "root contacted 93.184.216.34 and 127.0.0.1 about analysis of banana and al";
        assert_eq!(
            r.text(text),
            text,
            "ana inside a word, al (too short), root, public and loopback IPs"
        );
        assert!(r.text("fd00::1 and fe80::1").matches("ip-").count() == 2);
        assert_eq!(r.text("2001:4860:4860::8888"), "2001:4860:4860::8888");
    }

    #[test]
    fn home_folders_become_tilde() {
        let r = redactor();
        assert_eq!(r.text("/home/ana/.ssh/id_ed25519"), "~/.ssh/id_ed25519");
        assert_eq!(
            r.text("opened /home/bruno and /root/x and /rooted"),
            "opened ~ and ~/x and /rooted"
        );
    }

    #[test]
    fn a_whole_tree_is_redacted_but_keys_are_not_and_ssid_fields_always_are() {
        let r = redactor();
        let mut tree = json!({
            "args": { "name": "ana's phone", "ssid": "CafeFree", "ip": "10.0.0.7" },
            "list": ["/home/ana/x", 5, null, true],
        });
        r.value(&mut tree);
        assert!(tree["args"]["ssid"].as_str().unwrap().starts_with("ssid-"));
        assert!(tree["args"]["ip"].as_str().unwrap().starts_with("ip-"));
        assert_eq!(tree["list"][0], "~/x");
        assert_eq!(tree["list"][1], 5);
        assert!(tree["args"].get("name").is_some());
    }

    #[test]
    fn a_kind_that_is_turned_off_is_left_as_it_is() {
        let r = Redactor::new(b"s".to_vec(), &["ana".into()], &[], &["mac".to_string()]);
        assert_eq!(r.text("ana at 192.168.1.1"), "ana at 192.168.1.1");
    }

    #[test]
    fn redaction_never_panics_on_odd_text() {
        let r = redactor();
        for text in [
            "",
            "\u{1f980} ana \u{0}",
            ":::",
            "...",
            "-",
            "ana.",
            "/home/",
            "/home/ana",
            "é/home/é",
        ] {
            let _ = r.text(text);
        }
    }
}
