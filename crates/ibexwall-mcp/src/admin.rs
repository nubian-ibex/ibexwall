// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-mcp token create` and `ibexwall-mcp tls-init`: what a person
//! runs to open the HTTP transport. Neither edits `/etc`: they print what to
//! paste, so the person stays the one who decides what the file says.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::token;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn flags<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| *a == name)
        .filter_map(|(i, _)| args.get(i + 1).map(String::as_str))
        .collect()
}

/// `token create --name N --client C [--id ID] [--expires YYYY-MM-DD] [--secret-stdin]`.
/// With `--secret-stdin` the person's own secret is read from standard
/// input (never from the command line, where `ps` and the shell history
/// would keep it); without it a 256-bit secret is generated.
pub fn token_create(args: &[String], stdin: &mut dyn Read) -> Result<String, String> {
    let name = flag(args, "--name").ok_or("--name is required (what this token is for)")?;
    let client = flag(args, "--client").ok_or("--client is required (a [[client]] in mcp.toml)")?;
    let id = match flag(args, "--id") {
        Some(id) => id.to_string(),
        None => token::random_bytes(4)
            .map_err(|e| e.to_string())?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .replace(|c: char| !c.is_ascii_alphanumeric(), ""),
    };
    let secret = if args.iter().any(|a| a == "--secret-stdin") {
        let mut text = String::new();
        stdin
            .take(512)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        Some(text.trim().to_string())
    } else {
        None
    };
    let created = token::create(
        &id,
        name,
        client,
        flag(args, "--expires"),
        secret.as_deref(),
    )?;
    Ok(format!(
        "Token (shown once; copy it now, only its hash is kept):\n\n  {}\n\nAdd this to /etc/ibexwall/mcp.toml, and make sure a [[client]] named \"{client}\" gives it the scopes you want:\n\n{}\nThe client sends it as `Authorization: Bearer <token>`. Keep it in an environment variable or your client's secret store, never in a file you commit. To revoke it, delete its [[token]] block.\n",
        created.token, created.stanza
    ))
}

/// `tls-init --host NAME... [--out DIR] [--days N]`: a self-signed
/// certificate and key for the HTTP transport, and the fingerprint a client
/// can pin. The key is written 0600.
pub fn tls_init(args: &[String]) -> Result<String, String> {
    let hosts = flags(args, "--host");
    if hosts.is_empty() {
        return Err(
            "--host is required (a name or address clients will use; repeat it for more)".into(),
        );
    }
    let days: u32 = flag(args, "--days")
        .map(|d| d.parse().map_err(|_| "--days is a number".to_string()))
        .transpose()?
        .unwrap_or(365);
    if !(1..=825).contains(&days) {
        return Err("--days is 1 to 825".into());
    }
    let out = Path::new(flag(args, "--out").unwrap_or("."));
    let mut params =
        rcgen::CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
            .map_err(|e| e.to_string())?;
    let now = ibexwall_sys::Clock::unix_now(&ibexwall_sys::RealClock);
    let day = |secs: i64| {
        let text = ibexwall_sys::format_rfc3339(secs);
        let n = |a: usize, b: usize| text[a..b].parse::<i32>().unwrap_or(1970);
        rcgen::date_time_ymd(n(0, 4), n(5, 7) as u8, n(8, 10) as u8)
    };
    params.not_before = day(now - 86_400);
    params.not_after = day(now + i64::from(days) * 86_400);
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let (cert_path, key_path) = (out.join("tls.crt"), out.join("tls.key"));
    std::fs::write(&cert_path, cert.pem()).map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&key_path)
        .map_err(|e| format!("{}: {e}", key_path.display()))?;
    std::io::Write::write_all(&mut key_file, key.serialize_pem().as_bytes())
        .map_err(|e| e.to_string())?;
    let fingerprint = Sha256::digest(cert.der().as_ref())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(format!(
        "Wrote {} and {} (key mode 0600), valid {days} days for: {}\n\nSHA-256 fingerprint (check it on the client before trusting this certificate):\n  {fingerprint}\n\nInstall them where mcp.toml points ([http] tls_cert and tls_key, /etc/ibexwall/mcp/ by default) with the key readable only by the account that runs `ibexwall-mcp --http`.\n",
        cert_path.display(),
        key_path.display(),
        hosts.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_token_is_generated_or_chosen_and_only_the_hash_is_printed_as_config() {
        let out = token_create(
            &args(&[
                "--name",
                "laptop",
                "--client",
                "opencode",
                "--expires",
                "2099-12-31",
            ]),
            &mut std::io::empty(),
        )
        .unwrap();
        let token = out
            .lines()
            .find(|l| l.trim().starts_with("ibx_"))
            .unwrap()
            .trim()
            .to_string();
        let (_, secret) = token::parse(&token).unwrap();
        assert!(
            out.contains("[[token]]")
                && out.contains("$argon2id$")
                && out.contains("expires = \"2099-12-31\"")
        );
        assert_eq!(
            out.matches(secret).count(),
            1,
            "the secret appears once, in the token line"
        );

        let mut chosen = std::io::Cursor::new(b"correct-horse-battery-staple-9\n".to_vec());
        let mine = token_create(
            &args(&[
                "--name",
                "me",
                "--client",
                "c",
                "--id",
                "mine",
                "--secret-stdin",
            ]),
            &mut chosen,
        )
        .unwrap();
        assert!(mine.contains("ibx_mine_correct-horse-battery-staple-9"));
        let weak = token_create(
            &args(&["--name", "me", "--client", "c", "--secret-stdin"]),
            &mut std::io::Cursor::new(b"password".to_vec()),
        );
        assert!(weak.is_err());
        assert!(token_create(&args(&["--client", "c"]), &mut std::io::empty()).is_err());
    }

    #[test]
    fn tls_init_writes_a_private_key_a_certificate_and_a_fingerprint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ibx-tls-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = tls_init(&args(&[
            "--host",
            "mcp.example",
            "--host",
            "10.0.0.5",
            "--out",
            dir.to_str().unwrap(),
            "--days",
            "30",
        ]))
        .unwrap();
        let mode = std::fs::metadata(dir.join("tls.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(out.contains("SHA-256 fingerprint") && out.contains("mcp.example, 10.0.0.5"));
        // The pair is accepted by the server's own loader.
        let config = crate::http::tls_config(
            dir.join("tls.crt").to_str().unwrap(),
            dir.join("tls.key").to_str().unwrap(),
        );
        assert!(config.is_ok(), "{:?}", config.err());
        assert!(tls_init(&args(&["--out", "x"])).is_err());
        assert!(tls_init(&args(&["--host", "a", "--days", "9999"])).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
