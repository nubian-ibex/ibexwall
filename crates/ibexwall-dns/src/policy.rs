// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decision the resolver takes for one query name, kept free of any
//! I/O so it can be tested exhaustively and swapped atomically.

use std::collections::HashSet;

/// Names that must never resolve because they signal "disable DoH" to
/// browsers. Firefox asks for the canary and turns its own DoH off when
/// it gets NXDOMAIN.
pub const DOH_CANARY: &str = "use-application-dns.net";

/// How a blocked name is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    /// NXDOMAIN (default).
    #[default]
    NxDomain,
    /// `0.0.0.0` for A and `::` for AAAA.
    NullAddress,
}

/// What to do with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Answer locally as blocked; the category tells the counters which
    /// list or rule matched.
    Block(Category),
    /// Ask the encrypted upstream.
    Forward,
}

/// Why a name is blocked (counters only; never a query log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// A block list entry.
    List,
    /// The browser DoH canary.
    Canary,
    /// A known DNS-over-HTTPS endpoint.
    DohEndpoint,
}

/// Block lists, allowlist and rules, compiled to hash sets of normalized
/// names. A name matches an entry when it equals it or is a subdomain.
#[derive(Debug, Default)]
pub struct Policy {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
    doh_endpoints: HashSet<String>,
    pub response: BlockResponse,
    /// When false the canary and DoH endpoints are not intercepted.
    pub block_doh: bool,
}

impl Policy {
    pub fn new(response: BlockResponse, block_doh: bool) -> Self {
        Self {
            response,
            block_doh,
            ..Self::default()
        }
    }

    pub fn block<I: IntoIterator<Item = String>>(&mut self, names: I) {
        self.blocked
            .extend(names.into_iter().filter_map(|n| normalize(&n)));
    }

    pub fn allow<I: IntoIterator<Item = String>>(&mut self, names: I) {
        self.allowed
            .extend(names.into_iter().filter_map(|n| normalize(&n)));
    }

    pub fn doh_endpoints<I: IntoIterator<Item = String>>(&mut self, names: I) {
        self.doh_endpoints
            .extend(names.into_iter().filter_map(|n| normalize(&n)));
    }

    /// Number of block entries (for status and tests).
    pub fn blocked_len(&self) -> usize {
        self.blocked.len()
    }

    /// Decides one query name. The allowlist always wins over blocks, so a
    /// user can repair a false positive without editing lists.
    pub fn decide(&self, name: &str) -> Verdict {
        let Some(name) = normalize(name) else {
            return Verdict::Forward;
        };
        if matches_suffix(&self.allowed, &name) {
            return Verdict::Forward;
        }
        if self.block_doh {
            if name == DOH_CANARY {
                return Verdict::Block(Category::Canary);
            }
            if matches_suffix(&self.doh_endpoints, &name) {
                return Verdict::Block(Category::DohEndpoint);
            }
        }
        if matches_suffix(&self.blocked, &name) {
            return Verdict::Block(Category::List);
        }
        Verdict::Forward
    }
}

/// Lowercase, no trailing dot, no empty labels. `None` for the root or an
/// unusable name.
pub fn normalize(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.split('.').any(str::is_empty) {
        return None;
    }
    Some(name)
}

/// True when `name` or any parent domain is in `set`.
fn matches_suffix(set: &HashSet<String>, name: &str) -> bool {
    if set.is_empty() {
        return false;
    }
    let mut rest = name;
    loop {
        if set.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, parent)) => rest = parent,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        let mut policy = Policy::new(BlockResponse::NxDomain, true);
        policy.block(["ads.example".to_string(), "Tracker.NET.".to_string()]);
        policy.allow(["ok.ads.example".to_string()]);
        policy.doh_endpoints(["dns.bad-doh.example".to_string()]);
        policy
    }

    #[test]
    fn blocks_exact_names_and_subdomains() {
        let policy = policy();
        assert_eq!(policy.decide("ads.example"), Verdict::Block(Category::List));
        assert_eq!(
            policy.decide("a.b.ads.example."),
            Verdict::Block(Category::List)
        );
        assert_eq!(policy.decide("TRACKER.net"), Verdict::Block(Category::List));
    }

    #[test]
    fn does_not_block_lookalikes_or_parents() {
        let policy = policy();
        assert_eq!(policy.decide("notads.example"), Verdict::Forward);
        assert_eq!(policy.decide("example"), Verdict::Forward);
        assert_eq!(policy.decide("ads.example.org"), Verdict::Forward);
    }

    #[test]
    fn allowlist_wins_over_a_block() {
        let policy = policy();
        assert_eq!(policy.decide("ok.ads.example"), Verdict::Forward);
        assert_eq!(policy.decide("x.ok.ads.example"), Verdict::Forward);
        assert_eq!(
            policy.decide("other.ads.example"),
            Verdict::Block(Category::List)
        );
    }

    #[test]
    fn canary_and_doh_endpoints_are_intercepted_when_enabled() {
        let policy = policy();
        assert_eq!(
            policy.decide("use-application-dns.net"),
            Verdict::Block(Category::Canary)
        );
        assert_eq!(
            policy.decide("dns.bad-doh.example"),
            Verdict::Block(Category::DohEndpoint)
        );
        let off = Policy::new(BlockResponse::NxDomain, false);
        assert_eq!(off.decide("use-application-dns.net"), Verdict::Forward);
    }

    #[test]
    fn unusable_names_are_forwarded_not_blocked() {
        let policy = policy();
        assert_eq!(policy.decide(""), Verdict::Forward);
        assert_eq!(policy.decide("."), Verdict::Forward);
        assert_eq!(policy.decide("a..b"), Verdict::Forward);
    }
}
