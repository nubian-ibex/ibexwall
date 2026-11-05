// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Access tokens for the HTTP transport. A token is `ibx_<id>_<secret>`:
//! the id picks one record in `mcp.toml`, so a request costs one hash check
//! and not one per token; the secret is checked against an Argon2id hash,
//! and only the hash is ever written down. The person can let IbexWall
//! generate the secret (256 random bits, the default) or choose their own
//! (long enough to be worth hashing), and sets a name, the client whose
//! scopes it gets and an optional expiry.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub const PREFIX: &str = "ibx_";
/// Shortest secret a person may choose, and how varied it has to be.
pub const MIN_SECRET: usize = 24;
const MIN_DISTINCT: usize = 12;

pub struct Created {
    /// Shown once, never stored.
    pub token: String,
    /// What goes into `/etc/ibexwall/mcp.toml`.
    pub stanza: String,
}

pub fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
    Ok(bytes)
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

pub fn valid_id(id: &str) -> bool {
    (3..=16).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn valid_secret_chars(secret: &str) -> bool {
    secret
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A secret the person chose: long and varied enough, and made of characters
/// that survive a header and a shell.
pub fn check_chosen_secret(secret: &str) -> Result<(), String> {
    if secret.len() < MIN_SECRET {
        return Err(format!("choose at least {MIN_SECRET} characters"));
    }
    if !valid_secret_chars(secret) {
        return Err("use only letters, digits, `-` and `_`".into());
    }
    let distinct = secret
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if distinct < MIN_DISTINCT {
        return Err("that secret repeats too much; use at least 12 different characters".into());
    }
    Ok(())
}

pub fn hash(secret: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(&random_bytes(16).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify(hash: &str, secret: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok()
    })
}

/// `ibx_<id>_<secret>` into `(id, secret)`.
pub fn parse(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    (valid_id(id) && secret.len() >= MIN_SECRET && valid_secret_chars(secret))
        .then_some((id, secret))
}

/// A new token. `secret` is the person's own choice, or `None` for a
/// generated one; `expires` is `YYYY-MM-DD`.
pub fn create(
    id: &str,
    name: &str,
    client: &str,
    expires: Option<&str>,
    secret: Option<&str>,
) -> Result<Created, String> {
    if !valid_id(id) {
        return Err("the id is 3 to 16 lowercase letters or digits".into());
    }
    if name.is_empty()
        || name.len() > 60
        || name.chars().any(char::is_control)
        || name.contains('"')
    {
        return Err("the name is 1 to 60 characters, without quotes".into());
    }
    if client.is_empty()
        || !client
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("the client is a name made of letters, digits, `-` and `_`".into());
    }
    if let Some(day) = expires
        && !valid_day(day)
    {
        return Err("the expiry is a date, YYYY-MM-DD".into());
    }
    let secret = match secret {
        Some(chosen) => {
            check_chosen_secret(chosen)?;
            chosen.to_string()
        }
        None => base64url(&random_bytes(32).map_err(|e| e.to_string())?),
    };
    let digest = hash(&secret)?;
    let mut stanza = format!(
        "[[token]]\nid = \"{id}\"\nname = \"{name}\"\nclient = \"{client}\"\nhash = \"{digest}\"\n"
    );
    if let Some(day) = expires {
        stanza.push_str(&format!("expires = \"{day}\"\n"));
    }
    Ok(Created {
        token: format!("{PREFIX}{id}_{secret}"),
        stanza,
    })
}

pub fn valid_day(day: &str) -> bool {
    let b = day.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && day
            .bytes()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && (1..=12).contains(&day[5..7].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&day[8..10].parse::<u32>().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_token_verifies_and_only_its_hash_is_stored() {
        let created = create("k1x", "laptop", "claude-code", Some("2099-01-01"), None).unwrap();
        let (id, secret) = parse(&created.token).unwrap();
        assert_eq!(id, "k1x");
        assert!(secret.len() >= 43, "256 random bits");
        let hash_line = created
            .stanza
            .lines()
            .find(|l| l.starts_with("hash"))
            .unwrap();
        assert!(hash_line.contains("$argon2id$"));
        assert!(
            !created.stanza.contains(secret),
            "the secret is never in the stanza"
        );
        let hash = hash_line.split('"').nth(1).unwrap();
        assert!(verify(hash, secret));
        assert!(!verify(hash, "not-the-secret-not-the-secret"));
        assert!(created.stanza.contains("expires = \"2099-01-01\""));
        // Two tokens are never alike.
        assert_ne!(
            create("k1x", "a", "c", None, None).unwrap().token,
            created.token
        );
    }

    #[test]
    fn a_chosen_secret_has_to_be_worth_hashing() {
        let ok = create(
            "mine",
            "me",
            "opencode",
            None,
            Some("correct-horse-battery-staple-9"),
        )
        .unwrap();
        assert!(ok.token.ends_with("correct-horse-battery-staple-9"));
        for (bad, why) in [
            ("short", "at least"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "repeats"),
            ("has spaces in it but is long enough", "only letters"),
            ("héllo-wörld-with-accents-1234", "only letters"),
        ] {
            let error = create("mine", "me", "c", None, Some(bad)).err().unwrap();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn hostile_names_ids_and_dates_are_refused() {
        for (id, name, client, day) in [
            ("A", "n", "c", None),
            ("ok1", "", "c", None),
            ("ok1", "has\"quote", "c", None),
            ("ok1", "line\nbreak", "c", None),
            ("ok1", "n", "bad client", None),
            ("ok1", "n", "c", Some("tomorrow")),
            ("ok1", "n", "c", Some("2026-13-01")),
        ] {
            assert!(
                create(id, name, client, day, None).is_err(),
                "{id} {name} {client} {day:?}"
            );
        }
    }

    #[test]
    fn parsing_never_panics_and_rejects_what_is_not_a_token() {
        for bad in [
            "",
            "ibx_",
            "ibx__",
            "ibx_k1x_short",
            "Bearer x",
            "ibx_UP_aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ibx_k1x_\u{0}aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
        assert!(parse("ibx_k1x_abcdefghijklmnopqrstuvwxyz0123").is_some());
        assert!(!verify("not a hash", "whatever"));
    }

    #[test]
    fn base64url_matches_the_rfc_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }
}
