// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A guard for the rule that nothing leaves the machine in the clear
//! (ADR-0042): production code names no `http://` address, and only the
//! known places open network listeners. A new outbound or listening site
//! has to be added here on purpose, which is the moment to ask whether it is
//! encrypted end to end.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if !matches!(name, "target" | "tests" | "examples" | "node_modules") {
                    rust_files(&path, out);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" {
                out.push(path);
            }
        }
    }

    /// Production code of every crate and plugin: what comes before the
    /// first `#[cfg(test)]` of each file.
    fn production() -> Vec<(String, String)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for top in ["crates", "plugins"] {
            rust_files(&root.join(top), &mut files);
        }
        files
            .into_iter()
            .filter_map(|path| {
                let text = std::fs::read_to_string(&path).ok()?;
                let code = text.split("#[cfg(test)]").next().unwrap_or("").to_string();
                let name = path
                    .strip_prefix(&root)
                    .ok()?
                    .to_string_lossy()
                    .replace("/./", "/");
                Some((name, code))
            })
            .collect()
    }

    #[test]
    fn no_production_code_names_a_plaintext_http_address() {
        let mut offenders = Vec::new();
        for (file, code) in production() {
            for (n, line) in code.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                // A refusal message may mention the scheme; an address may not.
                if line.contains("\"http://")
                    && !line.contains("https://")
                    && !line.contains("must start with")
                {
                    offenders.push(format!("{file}:{}: {}", n + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "plaintext http addresses:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn only_the_known_places_listen_on_the_network() {
        // The resolver listens on a loopback address only; the MCP server
        // listens where the person put `[http] listen`, TLS only.
        let allowed = ["ibexwall-dns/src/main.rs", "ibexwall-mcp/src/main.rs"];
        let mut offenders = Vec::new();
        for (file, code) in production() {
            let listens = [
                "TcpListener::bind",
                "UdpSocket::bind",
                "TcpListener::from_std",
            ]
            .iter()
            .any(|needle| code.contains(needle));
            if listens && !allowed.iter().any(|a| file.ends_with(a)) {
                offenders.push(file);
            }
        }
        assert!(
            offenders.is_empty(),
            "unexpected network listeners (see ADR-0042): {offenders:?}"
        );
    }

    #[test]
    fn the_resolver_binds_only_to_its_loopback_address() {
        assert!(ibexwall_proto::names::DNS_BIND_ADDR.starts_with("127."));
    }

    #[test]
    fn the_mcp_http_transport_has_no_plain_mode() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let http = std::fs::read_to_string(root.join("crates/ibexwall-mcp/src/http.rs")).unwrap();
        let main = std::fs::read_to_string(root.join("crates/ibexwall-mcp/src/main.rs")).unwrap();
        // The only way to serve is through the TLS acceptor.
        assert!(http.contains("TlsAcceptor") && !http.contains("serve_connection(listener"));
        assert!(main.contains("tls_config") && !main.contains("allow_plain"));
    }
}
