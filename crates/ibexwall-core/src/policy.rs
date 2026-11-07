// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
// SPDX-License-Identifier: GPL-3.0-or-later

//! Managed-mode policy bundle verification (F11b, spec §4.14).
//!
//! The bundle arrives as JSON, is canonicalized with JCS (RFC 8785)
//! without the detached `signature` field, and is signed with ed25519.
//! The core verifies it itself against anchors in
//! `/etc/ibexwall/trust/<key_id>.pub` (minisign public-key wire format,
//! the same format the plugin trust anchor uses), refuses an expired
//! bundle and refuses a version older than the one already applied
//! (anti-rollback). Nothing is fetched over the network, ever.

use std::path::Path;

use ibexwall_proto::PolicyBundle;

/// The minisign public-key algorithm bytes: `Ed`.
const KEY_ALG_ED: [u8; 2] = [0x45, 0x64];

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PolicyVerifyError {
    #[error("the bundle is structurally invalid: {0}")]
    Invalid(#[from] ibexwall_proto::PolicyError),
    #[error("no trust anchor named `{0}`")]
    UnknownKey(String),
    #[error("the trust anchor `{0}` is not a valid public key")]
    BadAnchor(String),
    #[error("the bundle carries no signature")]
    Unsigned,
    #[error("unsupported signature algorithm `{0}` (expected ed25519)")]
    BadAlg(String),
    #[error("the signature does not cover the bundle")]
    BadSignature,
    #[error("the bundle expired {0}")]
    Expired(String),
    #[error("version {offered} is older than the applied {current}")]
    VersionRollback { current: u64, offered: u64 },
}

/// Reads a minisign-format public key file (comment line, then base64
/// of `Ed` + key id + the 32-byte ed25519 key) and returns the raw key.
fn anchor_public_key(path: &Path) -> Result<[u8; 32], PolicyVerifyError> {
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bad = || PolicyVerifyError::BadAnchor(name.clone());
    let text = std::fs::read_to_string(path).map_err(|_| bad())?;
    // The base64 payload is the last non-empty line.
    let payload = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(bad)?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .map_err(|_| bad())?;
    if bytes.len() != 42 || bytes[0..2] != KEY_ALG_ED {
        return Err(bad());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[10..42]);
    Ok(key)
}

/// Verifies a bundle against the trust anchors: structure, signature,
/// expiry and anti-rollback. `anchor_dir` holds `<key_id>.pub` files;
/// `current_version` is the version already applied (if any).
pub fn verify_bundle(
    bundle: &PolicyBundle,
    anchor_dir: &Path,
    current_version: Option<u64>,
    now_unix: i64,
) -> Result<(), PolicyVerifyError> {
    bundle.validate()?;
    let signature = bundle.signature.as_ref().ok_or(PolicyVerifyError::Unsigned)?;
    if signature.alg != "ed25519" {
        return Err(PolicyVerifyError::BadAlg(signature.alg.clone()));
    }
    if let Some(current) = current_version
        && bundle.version < current
    {
        return Err(PolicyVerifyError::VersionRollback {
            current,
            offered: bundle.version,
        });
    }
    // The core's own clock decides expiry; the issuer's word is not taken.
    if crate::compliance::parse_unix(&bundle.expires_at) <= now_unix {
        return Err(PolicyVerifyError::Expired(bundle.expires_at.clone()));
    }
    let anchor_path = anchor_dir.join(format!("{}.pub", signature.key_id));
    if !anchor_path.is_file() {
        return Err(PolicyVerifyError::UnknownKey(signature.key_id.clone()));
    }
    let key_bytes = anchor_public_key(&anchor_path)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| PolicyVerifyError::BadAnchor(signature.key_id.clone()))?;
    use base64::Engine as _;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature.value.trim())
        .map_err(|_| PolicyVerifyError::BadSignature)?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| PolicyVerifyError::BadSignature)?;
    // The signature covers the JCS canonicalization of the bundle
    // without the detached `signature` field.
    let mut signed = serde_json::to_value(bundle).map_err(|_| PolicyVerifyError::BadSignature)?;
    signed
        .as_object_mut()
        .map(|object| object.remove("signature"));
    let payload = serde_jcs::to_vec(&signed).map_err(|_| PolicyVerifyError::BadSignature)?;
    use ed25519_dalek::Verifier as _;
    key.verify(&payload, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| PolicyVerifyError::BadSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ibx-policy-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Fixture {
        dir: std::path::PathBuf,
        key: ed25519_dalek::SigningKey,
        key_id: &'static str,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = tempdir(tag);
            // A deterministic seed keeps the test reproducible; the key
            // is only as strong as it needs to be for the fixture.
            let mut seed = [0u8; 32];
            for (i, b) in tag.bytes().take(8).enumerate() {
                seed[i] = b;
            }
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let key_id = "test-org-2026";
            let mut pub_bytes = Vec::with_capacity(42);
            pub_bytes.extend_from_slice(&KEY_ALG_ED);
            pub_bytes.extend_from_slice(&[0u8; 8]);
            pub_bytes.extend_from_slice(key.verifying_key().as_bytes());
            use base64::Engine as _;
            let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
            std::fs::create_dir_all(dir.join("trust")).unwrap();
            std::fs::write(
                dir.join("trust").join(format!("{key_id}.pub")),
                format!("untrusted comment: test\n{pub_b64}\n"),
            )
            .unwrap();
            Self { dir, key, key_id }
        }

        fn bundle(&self, version: u64, expires: &str) -> PolicyBundle {
            let mut bundle = PolicyBundle {
                schema: ibexwall_proto::policy::POLICY_SCHEMA.into(),
                org: ibexwall_proto::policy::OrgIdentity {
                    id: "acme".into(),
                    name: "Acme".into(),
                },
                version,
                issued_at: "2026-11-01T12:00:00Z".into(),
                expires_at: expires.into(),
                settings: serde_json::json!({
                    "net.dns": { "upstream": "https://dns.acme.internal/dns-query" }
                }),
                locks: vec!["net.dns.upstream".into()],
                report: Default::default(),
                signature: None,
            };
            let mut signed = serde_json::to_value(&bundle).unwrap();
            signed.as_object_mut().unwrap().remove("signature");
            let payload = serde_jcs::to_vec(&signed).unwrap();
            use base64::Engine as _;
            bundle.signature = Some(ibexwall_proto::policy::BundleSignature {
                alg: "ed25519".into(),
                key_id: self.key_id.into(),
                value: base64::engine::general_purpose::STANDARD
                    .encode(self.key.sign(&payload).to_bytes()),
            });
            bundle
        }

        fn verify(
            &self,
            bundle: &PolicyBundle,
            current: Option<u64>,
            now: i64,
        ) -> Result<(), PolicyVerifyError> {
            verify_bundle(bundle, &self.dir.join("trust"), current, now)
        }
    }

    const NOW: i64 = 1_795_000_000;

    #[test]
    fn a_signed_bundle_from_a_known_key_verifies() {
        let fixture = Fixture::new("ok");
        let bundle = fixture.bundle(7, "2026-12-01T12:00:00Z");
        fixture.verify(&bundle, None, NOW).unwrap();
    }

    #[test]
    fn a_tampered_bundle_fails() {
        let fixture = Fixture::new("tamper");
        let mut bundle = fixture.bundle(7, "2026-12-01T12:00:00Z");
        bundle.locks.push("net.firewall.*".into());
        assert_eq!(
            fixture.verify(&bundle, None, NOW),
            Err(PolicyVerifyError::BadSignature)
        );
    }

    #[test]
    fn an_expired_bundle_is_refused() {
        let fixture = Fixture::new("expired");
        let bundle = fixture.bundle(7, "2026-11-01T13:00:00Z");
        assert!(matches!(
            fixture.verify(&bundle, None, NOW),
            Err(PolicyVerifyError::Expired(_))
        ));
    }

    #[test]
    fn an_older_version_is_refused() {
        let fixture = Fixture::new("rollback");
        let bundle = fixture.bundle(3, "2026-12-01T12:00:00Z");
        assert_eq!(
            fixture.verify(&bundle, Some(7), NOW),
            Err(PolicyVerifyError::VersionRollback {
                current: 7,
                offered: 3
            })
        );
        // The same version is allowed: applying a re-issued bundle is
        // an operator's legitimate move.
        fixture.verify(&fixture.bundle(7, "2026-12-01T12:00:00Z"), Some(7), NOW).unwrap();
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let fixture = Fixture::new("unknown");
        let mut bundle = fixture.bundle(7, "2026-12-01T12:00:00Z");
        bundle.signature.as_mut().unwrap().key_id = "other-org".into();
        assert_eq!(
            fixture.verify(&bundle, None, NOW),
            Err(PolicyVerifyError::UnknownKey("other-org".into()))
        );
    }

    #[test]
    fn an_unsigned_bundle_is_refused() {
        let fixture = Fixture::new("unsigned");
        let bundle = fixture.bundle(7, "2026-12-01T12:00:00Z");
        let mut unsigned = bundle.clone();
        unsigned.signature = None;
        assert_eq!(
            fixture.verify(&unsigned, None, NOW),
            Err(PolicyVerifyError::Unsigned)
        );
    }
}
