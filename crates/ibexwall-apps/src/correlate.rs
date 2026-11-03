// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IP to domain correlation (spec section 4.8): the resolver reports each
//! answer, the monitor joins connections against it. Time based and
//! honest: a miss stays a miss ("unresolved"), nothing is guessed.

use std::collections::HashMap;
use std::net::IpAddr;

/// Applications often connect after the record's TTL ran out (pooled
/// clients, long-lived processes); keep answers this much longer.
const GRACE_SECONDS: u64 = 120;

/// Upper bound on remembered addresses.
const CAPACITY: usize = 16_384;

#[derive(Debug, Default)]
pub struct Correlator {
    map: HashMap<IpAddr, (String, u64)>,
}

/// Normalizes an untrusted domain: lowercase, no trailing dot, printable
/// ASCII labels only. `None` when it cannot be a hostname.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
    valid.then_some(name)
}

impl Correlator {
    /// Remembers that `ip` was answered for `domain` with `ttl` seconds,
    /// at unix time `now`. A newer answer replaces an older one.
    pub fn learn(&mut self, ip: IpAddr, domain: &str, ttl: u32, now: u64) {
        let Some(domain) = normalize_domain(domain) else {
            return;
        };
        if self.map.len() >= CAPACITY && !self.map.contains_key(&ip) {
            self.map.retain(|_, (_, expires)| *expires > now);
            if self.map.len() >= CAPACITY {
                // Still full of live entries: start over rather than grow.
                self.map.clear();
            }
        }
        self.map
            .insert(ip, (domain, now + u64::from(ttl) + GRACE_SECONDS));
    }

    /// The domain `ip` was last answered for, while still believable.
    pub fn lookup(&self, ip: IpAddr, now: u64) -> Option<&str> {
        match self.map.get(&ip) {
            Some((domain, expires)) if *expires > now => Some(domain),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_learned_answer_is_found_until_ttl_plus_grace() {
        let mut c = Correlator::default();
        c.learn(ip("93.184.216.34"), "Example.COM.", 60, 1000);
        assert_eq!(c.lookup(ip("93.184.216.34"), 1000), Some("example.com"));
        assert_eq!(
            c.lookup(ip("93.184.216.34"), 1000 + 60 + 119),
            Some("example.com")
        );
        assert_eq!(c.lookup(ip("93.184.216.34"), 1000 + 60 + 120), None);
    }

    #[test]
    fn a_miss_is_a_miss() {
        let c = Correlator::default();
        assert_eq!(c.lookup(ip("10.0.0.1"), 0), None);
    }

    #[test]
    fn the_newest_answer_wins_for_a_shared_address() {
        let mut c = Correlator::default();
        c.learn(ip("1.2.3.4"), "a.example", 30, 100);
        c.learn(ip("1.2.3.4"), "b.example", 30, 110);
        assert_eq!(c.lookup(ip("1.2.3.4"), 111), Some("b.example"));
    }

    #[test]
    fn hostile_names_are_dropped() {
        let mut c = Correlator::default();
        for name in ["", ".", "a b", "x\u{1b}[31m", "é.example", &"a".repeat(300)] {
            c.learn(ip("1.2.3.4"), name, 30, 0);
        }
        assert!(c.is_empty());
        assert_eq!(
            normalize_domain("_dmarc.Example.com"),
            Some("_dmarc.example.com".into())
        );
    }

    #[test]
    fn memory_stays_bounded() {
        let mut c = Correlator::default();
        for n in 0..(CAPACITY as u32 + 10) {
            c.learn(IpAddr::from(n.to_be_bytes()), "host.example", 3600, 0);
        }
        assert!(c.len() <= CAPACITY);
    }

    #[test]
    fn expired_entries_are_reclaimed_before_live_ones_are_lost() {
        let mut c = Correlator::default();
        for n in 0..CAPACITY as u32 {
            c.learn(IpAddr::from(n.to_be_bytes()), "old.example", 1, 0);
        }
        c.learn(ip("203.0.113.9"), "new.example", 60, 10_000);
        assert_eq!(c.lookup(ip("203.0.113.9"), 10_000), Some("new.example"));
        assert_eq!(c.len(), 1);
    }
}
