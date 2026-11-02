// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Block list parsing. Lists are untrusted input: every line is validated
//! as a plain DNS name and anything else is skipped, never interpreted.
//! Three formats are understood and detected per line:
//!
//! - hosts: `0.0.0.0 ads.example` (also `127.0.0.1`, `::`, `::1`);
//! - domain list: `ads.example`;
//! - adblock: `||ads.example^` (block) and `@@||ok.example^` (allow).
//!
//! Adblock rules that carry options (`$third-party`), paths, wildcards or
//! cosmetic filters cannot be expressed at DNS level and are skipped.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::policy::normalize;

/// Largest list accepted from the network or disk (bytes).
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;
/// Most entries kept from one list.
pub const MAX_ENTRIES: usize = 2_000_000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub block: HashSet<String>,
    /// Adblock exceptions (`@@||name^`); merged into the allowlist.
    pub allow: HashSet<String>,
    /// Lines that were not usable (comments and blanks excluded).
    pub skipped: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("list is larger than {MAX_LIST_BYTES} bytes")]
    TooLarge,
    #[error("list is not valid UTF-8 text")]
    NotText,
    #[error("list has more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    #[error("no usable entries found; refusing to replace the current list")]
    Empty,
}

/// Parses a whole list. An empty result is an error so that a truncated or
/// wrong download can never replace a working list with nothing.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(ParseError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::NotText)?;
    let mut parsed = Parsed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        match parse_line(line) {
            Some(Rule::Block(name)) => {
                parsed.block.insert(name);
            }
            Some(Rule::Allow(name)) => {
                parsed.allow.insert(name);
            }
            None => parsed.skipped += 1,
        }
        if parsed.block.len() + parsed.allow.len() > MAX_ENTRIES {
            return Err(ParseError::TooManyEntries);
        }
    }
    if parsed.block.is_empty() && parsed.allow.is_empty() {
        return Err(ParseError::Empty);
    }
    Ok(parsed)
}

enum Rule {
    Block(String),
    Allow(String),
}

fn parse_line(line: &str) -> Option<Rule> {
    if let Some(rest) = line.strip_prefix("@@||") {
        return adblock_name(rest).map(Rule::Allow);
    }
    if let Some(rest) = line.strip_prefix("||") {
        return adblock_name(rest).map(Rule::Block);
    }
    // Trailing comments are common in hosts files.
    let line = line.split('#').next().unwrap_or("").trim();
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    match (first.parse::<IpAddr>(), fields.next()) {
        // hosts: only null or loopback addresses mean "block"; a real
        // address would be a redirect, which is not a block list.
        (Ok(ip), Some(name)) if ip.is_unspecified() || ip.is_loopback() => {
            valid_name(name).map(Rule::Block)
        }
        (Ok(_), _) => None,
        (Err(_), None) => valid_name(first).map(Rule::Block),
        (Err(_), Some(_)) => None,
    }
}

/// `example.com^` is a domain rule; any option, path or wildcard is not.
fn adblock_name(rest: &str) -> Option<String> {
    let name = rest.strip_suffix('^')?;
    valid_name(name)
}

/// A host name usable as a block entry: letters, digits, `-` and `_`,
/// labels of 1 to 63 bytes, at most 253 bytes, at least two labels, and
/// not an IP address.
fn valid_name(raw: &str) -> Option<String> {
    let name = normalize(raw)?;
    if name.len() > 253 || name.parse::<IpAddr>().is_ok() || !name.contains('.') {
        return None;
    }
    let ok = name.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn parses_hosts_files() {
        let text = "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example\n\
                    :: v6.example # trailing\n0.0.0.0 Tracker.Example.\n\
                    192.0.2.1 redirect.example\n";
        let parsed = parse(text.as_bytes()).unwrap();
        // `localhost` has no dot, `redirect.example` is a redirect.
        assert_eq!(
            parsed.block,
            set(&["ads.example", "v6.example", "tracker.example"])
        );
        assert_eq!(parsed.skipped, 2);
    }

    #[test]
    fn parses_domain_lists() {
        let parsed = parse(b"ads.example\n\n! note\ntracker.net\nnot a domain\n").unwrap();
        assert_eq!(parsed.block, set(&["ads.example", "tracker.net"]));
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn parses_adblock_domain_rules_and_exceptions() {
        let text = "[Adblock Plus 2.0]\n||ads.example^\n@@||ok.ads.example^\n\
                    ||opts.example^$third-party\n||path.example/ads^\n\
                    ||wild*.example^\n##.banner\n";
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.block, set(&["ads.example"]));
        assert_eq!(parsed.allow, set(&["ok.ads.example"]));
        // Header, options, path and wildcard rules are skipped; the
        // cosmetic `##` filter starts with `#` and counts as a comment.
        assert_eq!(parsed.skipped, 4);
    }

    #[test]
    fn rejects_unsafe_or_malformed_names() {
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = format!("{}.example", "a.".repeat(130));
        let text = format!(
            "0.0.0.0 {long_label}\n0.0.0.0 {long_name}\n0.0.0.0 bad_char!.example\n\
             0.0.0.0 a..b.example\n0.0.0.0 1.2.3.4\n0.0.0.0 ok.example\n"
        );
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.block, set(&["ok.example"]));
        assert_eq!(parsed.skipped, 5);
    }

    #[test]
    fn refuses_empty_binary_and_oversized_lists() {
        assert_eq!(parse(b"# only comments\n").unwrap_err(), ParseError::Empty);
        assert_eq!(parse(b"\xff\xfe\x00").unwrap_err(), ParseError::NotText);
        let big = vec![b'a'; MAX_LIST_BYTES + 1];
        assert_eq!(parse(&big).unwrap_err(), ParseError::TooLarge);
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Whatever the input, parsing never panics and every kept
            /// name is a valid lowercase host name.
            #[test]
            fn never_panics_and_keeps_only_valid_names(input in proptest::collection::vec(any::<u8>(), 0..2048)) {
                if let Ok(parsed) = parse(&input) {
                    for name in parsed.block.iter().chain(parsed.allow.iter()) {
                        prop_assert!(name.len() <= 253);
                        prop_assert!(name.contains('.'));
                        prop_assert_eq!(name, &name.to_ascii_lowercase());
                        prop_assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)));
                    }
                }
            }
        }
    }
}
