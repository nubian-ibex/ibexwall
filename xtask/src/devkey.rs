// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask devkey`: development trust anchor for plugin signatures
//! (spec §5.5 `--dev-key`). Generates an ed25519 keypair in minisign
//! wire format under `target/devkey/` and (re)signs every
//! `plugins/*/plugin.toml` next to itself. Never used by release
//! packaging; the official key is embedded with F10.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::Signer;

/// minisign signature algorithm bytes: `ED` (prehashed, BLAKE2b-64).
const SIG_ALG_PREHASHED: [u8; 2] = [0x45, 0x44];
/// Public key algorithm bytes: `Ed`.
const KEY_ALG: [u8; 2] = [0x45, 0x64];

pub fn run() -> Result<()> {
    let root = workspace_root();
    let dir = root.join("target").join("devkey");
    std::fs::create_dir_all(&dir)?;
    let pub_path = dir.join("dev.pub");
    let secret_path = dir.join("dev.key");

    let signing = ensure_keypair(&pub_path, &secret_path)?;
    println!("public key: {}", pub_path.display());
    println!("secret key: {}", secret_path.display());

    // Sign every dev plugin manifest.
    let plugins = root.join("plugins");
    let mut signed = 0;
    if plugins.is_dir() {
        for entry in std::fs::read_dir(&plugins)? {
            let manifest = entry?.path().join("plugin.toml");
            if manifest.is_file() {
                let bytes = std::fs::read(&manifest)?;
                let sig = sign(&signing, &bytes, "ibexwall dev plugin");
                std::fs::write(manifest.with_extension("toml.sig"), sig)?;
                signed += 1;
            }
        }
    }
    println!("signed {signed} plugin manifest(s)");
    println!(
        "start the daemon with: ibexwalld --dev-key={}",
        pub_path.display()
    );
    Ok(())
}

pub(crate) struct KeyPair {
    secret: ed25519_dalek::SigningKey,
    key_id: [u8; 8],
}

pub(crate) fn ensure_keypair(pub_path: &Path, secret_path: &Path) -> Result<KeyPair> {
    if pub_path.is_file() && secret_path.is_file() {
        let secret_b64 = std::fs::read_to_string(secret_path)?.trim().to_string();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(secret_b64)
            .context("decoding dev.key")?;
        let secret = ed25519_dalek::SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .context("dev.key must hold 32 bytes")?,
        );
        let key_id = key_id_for(&secret);
        return Ok(KeyPair { secret, key_id });
    }
    let mut secret_bytes = [0u8; 32];
    getrandom_fill(&mut secret_bytes)?;
    let secret = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let key_id = key_id_for(&secret);

    // Public key file: comment line + base64(42B).
    let mut pub_bytes = Vec::with_capacity(42);
    pub_bytes.extend_from_slice(&KEY_ALG);
    pub_bytes.extend_from_slice(&key_id);
    pub_bytes.extend_from_slice(secret.verifying_key().as_bytes());
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);
    std::fs::write(
        pub_path,
        format!("untrusted comment: ibexwall dev key\n{pub_b64}\n"),
    )?;

    // Secret key file: dev-only raw base64 (NOT the encrypted minisign
    // secret format; this key never leaves the build tree).
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret_bytes);
    std::fs::write(secret_path, format!("{secret_b64}\n"))?;
    println!("generated new dev keypair");
    Ok(KeyPair { secret, key_id })
}

fn key_id_for(secret: &ed25519_dalek::SigningKey) -> [u8; 8] {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(secret.verifying_key().as_bytes());
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&digest[..8]);
    key_id
}

/// Produces a 4-line minisign signature file for `data`.
pub(crate) fn sign(pair: &KeyPair, data: &[u8], comment: &str) -> String {
    sign_labelled(pair, data, comment, "ibexwall dev signature")
}

/// The same, with the untrusted comment saying what the signature is for.
pub(crate) fn sign_labelled(pair: &KeyPair, data: &[u8], comment: &str, label: &str) -> String {
    // Prehash: BLAKE2b-64 like real minisign (matches the `ED` alg).
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(64).expect("valid digest size");
    hasher.update(data);
    let mut prehash = [0u8; 64];
    hasher
        .finalize_variable(&mut prehash)
        .expect("64-byte output");
    let signature = pair.secret.sign(&prehash);

    // The global signature covers sig||comment WITHOUT the file prefix
    // (the verifier strips "trusted comment: " before checking).
    let trusted_comment = format!("trusted comment: {comment}");
    let mut global_input = Vec::with_capacity(64 + comment.len());
    global_input.extend_from_slice(&signature.to_bytes());
    global_input.extend_from_slice(comment.as_bytes());
    let global_signature = pair.secret.sign(&global_input);

    let mut sig_bytes = Vec::with_capacity(74);
    sig_bytes.extend_from_slice(&SIG_ALG_PREHASHED);
    sig_bytes.extend_from_slice(&pair.key_id);
    sig_bytes.extend_from_slice(&signature.to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
    let global_b64 = base64::engine::general_purpose::STANDARD.encode(global_signature.to_bytes());
    format!("untrusted comment: {label}\n{sig_b64}\n{trusted_comment}\n{global_b64}\n")
}

fn getrandom_fill(buf: &mut [u8]) -> Result<()> {
    // /dev/urandom read; no extra dependency.
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_with_minisign_verify() {
        let dir = std::env::temp_dir().join(format!("devkey-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pair = ensure_keypair(&dir.join("dev.pub"), &dir.join("dev.key")).unwrap();
        let data = b"kernel.ibexwall_test = 1\n";
        let sig_text = sign(&pair, data, "test");

        let public_text = std::fs::read_to_string(dir.join("dev.pub")).unwrap();
        let public_key = minisign_verify::PublicKey::decode(&public_text).unwrap();
        let signature = minisign_verify::Signature::decode(&sig_text).unwrap();
        assert!(public_key.verify(data, &signature, false).is_ok());

        // Tampered data must fail.
        assert!(public_key.verify(b"tampered", &signature, false).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
