// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A documented subset of `.ovpn` (ADR-0040, option 2): what a typical
//! provider profile uses and NetworkManager's OpenVPN plugin can express.
//! Every directive is either accepted and mapped, ignored because it is
//! harmless (and named as such), or refused by name with the reason, so a
//! profile never "imports" with a security setting silently dropped. What
//! runs commands or reaches outside NetworkManager (`up`, `plugin`,
//! `script-security`, proxies) is refused; certificates and keys must be
//! inline blocks, since the plugin cannot read files from a home folder.

use std::collections::BTreeMap;

pub const MAX_BLOCK: usize = 16 * 1024;
pub const MAX_TEXT: usize = 64 * 1024;
const MAX_REMOTES: usize = 4;

/// Directives that change nothing this import carries: accepted and ignored.
const HARMLESS: &[&str] = &[
    "client",
    "nobind",
    "persist-key",
    "persist-tun",
    "resolv-retry",
    "verb",
    "mute",
    "mute-replay-warnings",
    "auth-nocache",
    "remote-random",
    "explicit-exit-notify",
    "keepalive",
    "ping",
    "ping-restart",
    "float",
];

/// Refused, with the reason the person is given.
const REFUSED: &[(&str, &str)] = &[
    ("up", "it runs a command as root"),
    ("down", "it runs a command as root"),
    ("route-up", "it runs a command as root"),
    ("route-pre-down", "it runs a command as root"),
    ("ipchange", "it runs a command as root"),
    ("learn-address", "it runs a command as root"),
    ("client-connect", "it runs a command as root"),
    ("script-security", "it enables running commands"),
    ("plugin", "it loads code into OpenVPN"),
    ("tls-verify", "it runs a command as root"),
    ("setenv", "it feeds environment to scripts"),
    ("setenv-safe", "it feeds environment to scripts"),
    ("management", "it opens a control port"),
    ("http-proxy", "proxies are not supported"),
    ("socks-proxy", "proxies are not supported"),
    (
        "compress",
        "compression has been used to attack encrypted tunnels",
    ),
    (
        "comp-lzo",
        "compression has been used to attack encrypted tunnels",
    ),
    ("pkcs12", "use inline <ca>, <cert> and <key> blocks"),
    ("extra-certs", "use inline blocks"),
    ("dh", "a client does not use it"),
    ("secret", "static-key mode is not supported"),
    ("tun-mtu", "not carried by NetworkManager"),
    (
        "route",
        "routes come from the server, or are set in NetworkManager",
    ),
    (
        "redirect-gateway",
        "the server decides; set routing in NetworkManager",
    ),
    ("ifconfig", "static addressing is not supported"),
    (
        "connection",
        "multiple <connection> blocks are not supported",
    ),
];

/// The file forms of what must be inline.
const FILE_DIRECTIVES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-crypt",
    "tls-auth",
    "auth-user-pass",
];

#[derive(Debug, Default, PartialEq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub proto: String,
}

#[derive(Debug, Default, PartialEq)]
pub struct Profile {
    pub remotes: Vec<Remote>,
    pub ca: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub key_encrypted: bool,
    pub tls_crypt: Option<String>,
    pub tls_auth: Option<String>,
    pub key_direction: Option<u8>,
    pub cipher: Option<String>,
    pub data_ciphers: Option<String>,
    pub auth: Option<String>,
    pub tls_version_min: Option<String>,
    pub remote_cert_tls: bool,
    /// `auth-user-pass` without a file: NetworkManager asks for it.
    pub asks_for_login: bool,
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
}

fn proto_ok(proto: &str) -> Option<&'static str> {
    match proto {
        "udp" | "udp4" | "udp6" => Some("udp"),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" => Some("tcp"),
        _ => None,
    }
}

/// A PEM block with the labels this import accepts, nothing else.
fn pem_ok(text: &str, labels: &[&str]) -> Result<bool, String> {
    let trimmed = text.trim();
    if trimmed.len() > MAX_BLOCK {
        return Err("a certificate or key block is too large".into());
    }
    // OpenVPN's own key files start with comment lines; they carry nothing.
    let lines: Vec<&str> = trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .collect();
    if lines.len() < 3 {
        return Err("a block is too short to be PEM".into());
    }
    let (first, last) = (
        lines.first().copied().unwrap_or(""),
        lines.last().copied().unwrap_or(""),
    );
    let label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or("a block is not PEM (no BEGIN line)")?;
    if last != format!("-----END {label}-----") {
        return Err("a PEM block does not end where it began".into());
    }
    if !labels.contains(&label) {
        return Err(format!("`{label}` is not accepted here"));
    }
    let body_ok = lines[1..lines.len() - 1].iter().all(|l| {
        l.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'+' | b'/' | b'=' | b':' | b' ' | b',' | b'-' | b'.')
        })
    });
    if !body_ok {
        return Err("a PEM block holds characters that do not belong".into());
    }
    Ok(label.contains("ENCRYPTED"))
}

/// `a b c` directive line into `(directive, args)`; comments (`#`, `;`) cut.
fn directive(line: &str) -> Option<(String, Vec<&str>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_ascii_lowercase();
    Some((
        name,
        parts
            .take_while(|p| !p.starts_with('#') && !p.starts_with(';'))
            .collect(),
    ))
}

pub fn parse(text: &str) -> Result<Profile, String> {
    if text.len() > MAX_TEXT {
        return Err("the profile is too large".into());
    }
    let mut profile = Profile::default();
    let mut blocks: BTreeMap<String, String> = BTreeMap::new();
    let mut open: Option<(String, String)> = None;
    let mut default_proto = "udp".to_string();
    let mut client = false;
    for raw in text.lines() {
        if let Some((tag, body)) = open.as_mut() {
            if raw.trim() == format!("</{tag}>") {
                let (tag, body) = open.take().expect("open block");
                if blocks.insert(tag.clone(), body).is_some() {
                    return Err(format!("`<{tag}>` appears twice"));
                }
            } else {
                body.push_str(raw.trim_end());
                body.push('\n');
            }
            continue;
        }
        let line = raw.trim();
        if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>'))
            && !tag.starts_with('/')
        {
            if !["ca", "cert", "key", "tls-crypt", "tls-auth"].contains(&tag) {
                return Err(format!(
                    "`<{tag}>` is not supported (accepted: ca, cert, key, tls-crypt, tls-auth)"
                ));
            }
            open = Some((tag.to_string(), String::new()));
            continue;
        }
        let Some((name, args)) = directive(raw) else {
            continue;
        };
        if let Some((_, why)) = REFUSED.iter().find(|(d, _)| *d == name) {
            return Err(format!("`{name}` is not supported: {why}"));
        }
        if FILE_DIRECTIVES.contains(&name.as_str())
            && !(name == "auth-user-pass" && args.is_empty())
        {
            return Err(format!(
                "`{name}` points at a file; paste its content as an inline <{}> block instead",
                if name == "auth-user-pass" {
                    "login"
                } else {
                    &name
                }
            ));
        }
        match name.as_str() {
            "client" => client = true,
            "dev" => {
                if !args.first().is_some_and(|d| {
                    *d == "tun"
                        || d.starts_with("tun") && d[3..].bytes().all(|b| b.is_ascii_digit())
                }) {
                    return Err("only `dev tun` is supported".into());
                }
            }
            "proto" => {
                default_proto = proto_ok(args.first().copied().unwrap_or(""))
                    .ok_or("`proto` is udp or tcp")?
                    .to_string();
            }
            "remote" => {
                if profile.remotes.len() >= MAX_REMOTES {
                    return Err(format!("at most {MAX_REMOTES} `remote` lines"));
                }
                let host = args.first().copied().unwrap_or("");
                if !host_ok(host) {
                    return Err("`remote` needs a host name or address".into());
                }
                let port: u16 = args
                    .get(1)
                    .map_or(Ok(1194), |p| p.parse())
                    .map_err(|_| "`remote` port is not a number")?;
                if port == 0 {
                    return Err("`remote` port cannot be 0".into());
                }
                let proto = match args.get(2) {
                    Some(p) => proto_ok(p)
                        .ok_or("`remote` protocol is udp or tcp")?
                        .to_string(),
                    None => String::new(),
                };
                profile.remotes.push(Remote {
                    host: host.into(),
                    port,
                    proto,
                });
            }
            "remote-cert-tls" => {
                if args.first() != Some(&"server") {
                    return Err("`remote-cert-tls` is `server`".into());
                }
                profile.remote_cert_tls = true;
            }
            "cipher" => {
                let c = args.first().copied().unwrap_or("");
                if !name_ok(c)
                    || c.eq_ignore_ascii_case("none")
                    || c.to_ascii_uppercase().starts_with("BF")
                {
                    return Err(format!("cipher `{c}` is not acceptable"));
                }
                profile.cipher = Some(c.to_string());
            }
            "data-ciphers" => {
                let list = args.join("");
                if list.is_empty()
                    || !list
                        .split(':')
                        .all(|c| name_ok(c) && !c.eq_ignore_ascii_case("none"))
                {
                    return Err("`data-ciphers` is a colon-separated list of cipher names".into());
                }
                profile.data_ciphers = Some(list);
            }
            "auth" => {
                let a = args.first().copied().unwrap_or("").to_ascii_uppercase();
                if !["SHA256", "SHA384", "SHA512"].contains(&a.as_str()) {
                    return Err("`auth` is SHA256, SHA384 or SHA512".into());
                }
                profile.auth = Some(a);
            }
            "tls-version-min" => {
                let v = args.first().copied().unwrap_or("");
                if v != "1.2" && v != "1.3" {
                    return Err("`tls-version-min` is 1.2 or 1.3".into());
                }
                profile.tls_version_min = Some(v.into());
            }
            "key-direction" => {
                profile.key_direction = Some(match args.first().copied() {
                    Some("0") => 0,
                    Some("1") => 1,
                    _ => return Err("`key-direction` is 0 or 1".into()),
                });
            }
            "auth-user-pass" => profile.asks_for_login = true,
            other if HARMLESS.contains(&other) => {}
            other => {
                return Err(format!(
                    "`{other}` is not supported; only a documented subset of OpenVPN is imported"
                ));
            }
        }
    }
    if open.is_some() {
        return Err("a block is not closed".into());
    }
    if !client {
        return Err("the profile is not a `client` profile".into());
    }
    if profile.remotes.is_empty() {
        return Err("the profile has no `remote`".into());
    }
    for remote in &mut profile.remotes {
        if remote.proto.is_empty() {
            remote.proto = default_proto.clone();
        }
    }
    profile.ca = blocks.remove("ca").ok_or("the profile has no <ca> block")?;
    pem_ok(&profile.ca, &["CERTIFICATE"])?;
    if let Some(cert) = blocks.remove("cert") {
        pem_ok(&cert, &["CERTIFICATE"])?;
        profile.cert = Some(cert);
    }
    if let Some(key) = blocks.remove("key") {
        profile.key_encrypted = pem_ok(
            &key,
            &[
                "PRIVATE KEY",
                "RSA PRIVATE KEY",
                "EC PRIVATE KEY",
                "ENCRYPTED PRIVATE KEY",
            ],
        )?;
        profile.key = Some(key);
    }
    if profile.cert.is_some() != profile.key.is_some() {
        return Err("<cert> and <key> go together".into());
    }
    if profile.cert.is_none() && !profile.asks_for_login {
        return Err("the profile has no client certificate and no `auth-user-pass`".into());
    }
    if let Some(t) = blocks.remove("tls-crypt") {
        pem_ok(&t, &["OpenVPN Static key V1"])?;
        profile.tls_crypt = Some(t);
    }
    if let Some(t) = blocks.remove("tls-auth") {
        pem_ok(&t, &["OpenVPN Static key V1"])?;
        profile.tls_auth = Some(t);
    }
    if profile.tls_crypt.is_some() && profile.tls_auth.is_some() {
        return Err("`<tls-crypt>` and `<tls-auth>` together".into());
    }
    Ok(profile)
}

/// NetworkManager's `[vpn]` data for a parsed profile; `dir` holds the files.
pub fn keyfile_data(profile: &Profile, dir: &str) -> String {
    let remotes: Vec<String> = profile
        .remotes
        .iter()
        .map(|r| format!("{}:{}:{}", r.host, r.port, r.proto))
        .collect();
    let connection_type = match (profile.cert.is_some(), profile.asks_for_login) {
        (true, true) => "password-tls",
        (true, false) => "tls",
        _ => "password",
    };
    let mut out = format!(
        "service-type=org.freedesktop.NetworkManager.openvpn\nconnection-type={connection_type}\ndev=tun\nremote={}\nca={dir}/ca.pem\n",
        remotes.join(", ")
    );
    if profile.cert.is_some() {
        out.push_str(&format!("cert={dir}/cert.pem\nkey={dir}/key.pem\n"));
        // 2: NetworkManager asks for the key's passphrase each time.
        out.push_str(&format!(
            "cert-pass-flags={}\n",
            if profile.key_encrypted { 2 } else { 0 }
        ));
    }
    if profile.asks_for_login {
        out.push_str("password-flags=2\n");
    }
    if profile.remote_cert_tls {
        out.push_str("remote-cert-tls=server\n");
    }
    for (key, value) in [
        ("cipher", &profile.cipher),
        ("data-ciphers", &profile.data_ciphers),
        ("auth", &profile.auth),
        ("tls-version-min", &profile.tls_version_min),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{key}={value}\n"));
        }
    }
    if profile.tls_crypt.is_some() {
        out.push_str(&format!("tls-crypt={dir}/tls-crypt.key\n"));
    } else if profile.tls_auth.is_some() {
        out.push_str(&format!("ta={dir}/ta.key\n"));
        if let Some(direction) = profile.key_direction {
            out.push_str(&format!("ta-dir={direction}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQm9ndXM=\n-----END CERTIFICATE-----";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----";
    const CRYPT: &str = "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef0123456789abcdef\n-----END OpenVPN Static key V1-----";

    fn profile(extra: &str) -> String {
        format!(
            "client\ndev tun\nproto udp\nremote vpn.example.net 1194\nnobind\npersist-key\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3 # chatty\n{extra}\n<ca>\n{CA}\n</ca>\n<cert>\n{CA}\n</cert>\n<key>\n{KEY}\n</key>\n<tls-crypt>\n{CRYPT}\n</tls-crypt>\n"
        )
    }

    #[test]
    fn a_typical_provider_profile_is_understood_and_maps_to_networkmanager_keys() {
        let p = parse(&profile("")).unwrap();
        assert_eq!(
            p.remotes,
            [Remote {
                host: "vpn.example.net".into(),
                port: 1194,
                proto: "udp".into()
            }]
        );
        assert!(p.remote_cert_tls && p.cert.is_some() && p.tls_crypt.is_some() && !p.key_encrypted);
        let data = keyfile_data(&p, "/etc/ibexwall/vpn/openvpn/lab");
        for line in [
            "service-type=org.freedesktop.NetworkManager.openvpn",
            "connection-type=tls",
            "remote=vpn.example.net:1194:udp",
            "ca=/etc/ibexwall/vpn/openvpn/lab/ca.pem",
            "key=/etc/ibexwall/vpn/openvpn/lab/key.pem",
            "cert-pass-flags=0",
            "cipher=AES-256-GCM",
            "auth=SHA256",
            "tls-crypt=/etc/ibexwall/vpn/openvpn/lab/tls-crypt.key",
            "remote-cert-tls=server",
        ] {
            assert!(data.contains(line), "{line}\n{data}");
        }
    }

    #[test]
    fn what_runs_commands_or_weakens_the_tunnel_is_refused_by_name() {
        for (extra, name) in [
            ("up /etc/openvpn/up.sh", "up"),
            ("down /bin/true", "down"),
            ("script-security 2", "script-security"),
            ("plugin /usr/lib/openvpn/x.so", "plugin"),
            ("tls-verify /bin/true", "tls-verify"),
            ("setenv FOO bar", "setenv"),
            ("management 127.0.0.1 7505", "management"),
            ("http-proxy 10.0.0.1 3128", "http-proxy"),
            ("compress lz4", "compress"),
            ("comp-lzo", "comp-lzo"),
            ("pkcs12 /home/x/a.p12", "pkcs12"),
            ("redirect-gateway def1", "redirect-gateway"),
            ("cipher BF-CBC", "cipher"),
            ("cipher none", "cipher"),
            ("auth MD5", "auth"),
            ("tls-version-min 1.0", "tls-version-min"),
            ("dev tap", "dev"),
            ("some-new-thing 1", "some-new-thing"),
        ] {
            let error = parse(&profile(extra)).unwrap_err();
            assert!(error.contains(name), "{extra}: {error}");
        }
    }

    #[test]
    fn certificates_must_be_inline_and_well_formed() {
        for (replace, with, why) in [
            (
                "remote vpn.example.net 1194",
                "remote vpn.example.net 1194\nca /etc/ca.crt",
                "inline",
            ),
            (
                "remote vpn.example.net 1194",
                "remote vpn.example.net 1194\nauth-user-pass /etc/pass",
                "inline",
            ),
            (
                "-----END CERTIFICATE-----\n</ca>",
                "-----END PRIVATE KEY-----\n</ca>",
                "end",
            ),
            ("<ca>", "<ca>\nnot a pem", "PEM"),
            ("<ca>", "<dh>\nx\n</dh>\n<ca>", "<dh>"),
            (
                "</tls-crypt>",
                "</tls-crypt>\n<ca>\n-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n</ca>",
                "twice",
            ),
        ] {
            let text = profile("").replacen(replace, with, 1);
            let error = parse(&text).unwrap_err();
            assert!(error.contains(why), "{replace}: {error}");
        }
        assert!(
            parse("client\nremote a 1194\n")
                .unwrap_err()
                .contains("<ca>")
        );
        assert!(
            parse(&"x".repeat(MAX_TEXT + 1))
                .unwrap_err()
                .contains("large")
        );
        assert!(parse("remote a 1194\n").unwrap_err().contains("client"));
    }

    #[test]
    fn the_comment_lines_openvpn_writes_above_a_static_key_are_accepted() {
        let commented = profile("").replace(
            "-----BEGIN OpenVPN Static key V1-----",
            "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----",
        );
        assert!(parse(&commented).is_ok());
    }

    #[test]
    fn logins_and_encrypted_keys_are_asked_for_at_connect_time_never_stored() {
        let asks = profile("auth-user-pass");
        let p = parse(&asks).unwrap();
        assert!(p.asks_for_login);
        let data = keyfile_data(&p, "/d");
        assert!(data.contains("connection-type=password-tls") && data.contains("password-flags=2"));
        let encrypted = profile("")
            .replace(
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            )
            .replace(
                "-----END PRIVATE KEY-----",
                "-----END ENCRYPTED PRIVATE KEY-----",
            );
        let p = parse(&encrypted).unwrap();
        assert!(p.key_encrypted);
        assert!(keyfile_data(&p, "/d").contains("cert-pass-flags=2"));
        // No certificate and no login: nothing to authenticate with.
        let bare = "client\nremote a 1194\n<ca>\n".to_string() + CA + "\n</ca>\n";
        assert!(parse(&bare).unwrap_err().contains("no client certificate"));
    }

    #[test]
    fn remotes_default_to_the_profile_protocol_and_are_bounded() {
        let text = profile("remote b.example 443 tcp\nremote c.example");
        let p = parse(&text).unwrap();
        assert_eq!(
            p.remotes[1],
            Remote {
                host: "b.example".into(),
                port: 443,
                proto: "tcp".into()
            }
        );
        assert_eq!(
            p.remotes[2],
            Remote {
                host: "c.example".into(),
                port: 1194,
                proto: "udp".into()
            }
        );
        let many = profile(&"remote z.example 1194\n".repeat(5));
        assert!(parse(&many).unwrap_err().contains("at most"));
        for bad in [
            "remote ;rm 1194",
            "remote a 0",
            "remote a notaport",
            "remote a 1194 sctp",
        ] {
            assert!(parse(&profile(bad)).is_err(), "{bad}");
        }
    }
}
