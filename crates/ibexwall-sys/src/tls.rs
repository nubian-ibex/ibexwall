// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A self-signed certificate and its private key, made when a plan is
//! applied. The key exists only here and on disk: it is never part of a
//! plan, a preview, a log or a proposal.

use anyhow::{Result, anyhow};

pub struct KeyPair {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the certificate, `AA:BB:...`, for the client to check.
    pub fingerprint: String,
}

/// A name or an address a client will use; the certificate is valid for it.
pub fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }))
}

pub fn generate(hosts: &[String], days: u32, now_unix: i64) -> Result<KeyPair> {
    use sha2::{Digest, Sha256};
    let mut params = rcgen::CertificateParams::new(hosts.to_vec()).map_err(|e| anyhow!("{e}"))?;
    let day = |secs: i64| {
        let text = crate::format_rfc3339(secs);
        let n = |a: usize, b: usize| text[a..b].parse::<i32>().unwrap_or(1970);
        rcgen::date_time_ymd(n(0, 4), n(5, 7) as u8, n(8, 10) as u8)
    };
    params.not_before = day(now_unix - 86_400);
    params.not_after = day(now_unix + i64::from(days) * 86_400);
    let key = rcgen::KeyPair::generate().map_err(|e| anyhow!("{e}"))?;
    let cert = params.self_signed(&key).map_err(|e| anyhow!("{e}"))?;
    let fingerprint = Sha256::digest(cert.der().as_ref())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(KeyPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_made_with_a_fingerprint_and_hosts_are_checked() {
        let pair = generate(
            &["mcp.example".into(), "10.0.0.5".into()],
            30,
            1_800_000_000,
        )
        .unwrap();
        assert!(pair.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pair.key_pem.contains("PRIVATE KEY"));
        assert_eq!(pair.fingerprint.split(':').count(), 32);
        for good in ["mcp.example", "10.0.0.5", "localhost", "::1", "a-b.c"] {
            assert!(valid_host(good), "{good}");
        }
        for bad in ["", "-a", "a b", "a..b", "x;y", "a/b", &"a".repeat(64)] {
            assert!(!valid_host(bad), "{bad}");
        }
    }
}
