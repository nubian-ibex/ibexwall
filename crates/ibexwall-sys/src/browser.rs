// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Browser DoH policies: one known file per browser, one exact content.
//! A plugin never writes free-form policy JSON; it names a browser and the
//! core maps that to the file the browser's own documentation defines.
//!
//! Paths verified from each vendor's documentation, 2026-11-02:
//! - Firefox: https://mozilla.github.io/policy-templates/ (system-wide
//!   `/etc/firefox/policies/policies.json`, policy `DNSOverHTTPS`).
//! - Chromium family: https://www.chromium.org/administrators/linux-quick-start/
//!   (`<policy dir>/policies/managed/*.json`, policy `DnsOverHttpsMode`;
//!   Chrome `/etc/opt/chrome`, Chromium `/etc/chromium`, Ubuntu's package
//!   `/etc/chromium-browser`).
//! - Brave: https://support.brave.app/hc/en-us/articles/360039248271
//!   (`/etc/brave/policies/managed/`).
//! - Edge: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
//!   (`/etc/opt/edge/policies/managed/`, policy `DnsOverHttpsMode`).

use serde_json::Value;

pub struct Target {
    pub browser: &'static str,
    /// The file the browser reads.
    pub path: &'static str,
    /// The exact policy content that turns the browser's own DoH off.
    pub content: &'static str,
}

/// Every browser IbexWall knows how to steer, with its own file name where
/// the format allows one (so an administrator's files stay untouched).
pub const TARGETS: &[Target] = &[
    Target {
        browser: "firefox",
        path: "/etc/firefox/policies/policies.json",
        content: r#"{"policies":{"DNSOverHTTPS":{"Enabled":false}}}"#,
    },
    Target {
        browser: "chrome",
        path: "/etc/opt/chrome/policies/managed/ibexwall-dns.json",
        content: r#"{"DnsOverHttpsMode":"off"}"#,
    },
    Target {
        browser: "chromium",
        path: "/etc/chromium/policies/managed/ibexwall-dns.json",
        content: r#"{"DnsOverHttpsMode":"off"}"#,
    },
    Target {
        // Ubuntu's repackaged Chromium reads this directory instead.
        browser: "chromium-browser",
        path: "/etc/chromium-browser/policies/managed/ibexwall-dns.json",
        content: r#"{"DnsOverHttpsMode":"off"}"#,
    },
    Target {
        browser: "brave",
        path: "/etc/brave/policies/managed/ibexwall-dns.json",
        content: r#"{"DnsOverHttpsMode":"off"}"#,
    },
    Target {
        browser: "edge",
        path: "/etc/opt/edge/policies/managed/ibexwall-dns.json",
        content: r#"{"DnsOverHttpsMode":"off"}"#,
    },
];

pub fn target(browser: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.browser == browser)
}

/// The policy value a plugin must send: exactly the DoH-off content.
pub fn doh_off(browser: &str) -> Option<Value> {
    target(browser).and_then(|target| serde_json::from_str(target.content).ok())
}

/// True when `existing` is exactly what IbexWall writes. Firefox's file
/// name is fixed, so an administrator's policies.json must never be
/// touched; anything that is not ours is refused.
pub fn is_ours(browser: &str, existing: &[u8]) -> bool {
    target(browser).is_some_and(|target| existing == target.content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_browser_has_a_distinct_path_and_valid_exact_json() {
        let mut paths = std::collections::HashSet::new();
        for target in TARGETS {
            assert!(target.path.starts_with("/etc/"), "{}", target.browser);
            assert!(
                paths.insert(target.path),
                "{} reuses {}",
                target.browser,
                target.path
            );
            let policy: Value = serde_json::from_str(target.content).unwrap();
            assert_eq!(policy, doh_off(target.browser).unwrap());
        }
    }

    #[test]
    fn firefox_disables_dnsoverhttps_and_the_others_set_the_mode() {
        let firefox = doh_off("firefox").unwrap();
        assert_eq!(firefox["policies"]["DNSOverHTTPS"]["Enabled"], false);
        for browser in ["chrome", "chromium", "chromium-browser", "brave", "edge"] {
            assert_eq!(
                doh_off(browser).unwrap()["DnsOverHttpsMode"],
                "off",
                "{browser}"
            );
        }
        assert!(doh_off("netscape").is_none());
    }

    #[test]
    fn foreign_content_is_recognized_as_not_ours() {
        assert!(is_ours("firefox", TARGETS[0].content.as_bytes()));
        assert!(!is_ours(
            "firefox",
            b"{\"policies\":{\"BlockAboutConfig\":true}}"
        ));
        assert!(!is_ours("chrome", b"{}"));
        assert!(!is_ours("unknown", b"anything"));
    }
}
