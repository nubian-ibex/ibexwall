// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexctl mcp config <client>`: what to paste to connect an assistant, and
//! the matching `/etc/ibexwall/mcp.toml` stanza. Nothing here talks to the
//! daemon or changes a file; the person copies what they want.

use clap::ValueEnum;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum McpClient {
    ClaudeCode,
    Opencode,
    Vscode,
}

impl McpClient {
    /// The name the server uses to pick scopes (`--client`).
    pub fn name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Opencode => "opencode",
            Self::Vscode => "vscode",
        }
    }

    fn file(self) -> &'static str {
        match self {
            Self::ClaudeCode => ".mcp.json (project) or ~/.claude.json",
            Self::Opencode => "opencode.json (project) or ~/.config/opencode/opencode.json",
            Self::Vscode => ".vscode/mcp.json",
        }
    }

    /// The client reaching a server over HTTPS: the token comes from the
    /// environment or a prompt, never from the file.
    fn remote_snippet(self, url: &str) -> Value {
        match self {
            Self::ClaudeCode => json!({ "mcpServers": { "ibexwall": {
                "type": "http", "url": url,
                "headers": { "Authorization": "Bearer ${IBEXWALL_MCP_TOKEN}" } } } }),
            Self::Opencode => json!({ "mcp": { "ibexwall": {
                "type": "remote", "url": url, "enabled": true,
                "headers": { "Authorization": "Bearer {env:IBEXWALL_MCP_TOKEN}" } } } }),
            Self::Vscode => json!({
                "inputs": [{ "type": "promptString", "id": "ibexwall-token",
                    "description": "IbexWall MCP token", "password": true }],
                "servers": { "ibexwall": { "type": "http", "url": url,
                    "headers": { "Authorization": "Bearer ${input:ibexwall-token}" } } } }),
        }
    }

    fn snippet(self) -> Value {
        let name = self.name();
        match self {
            Self::ClaudeCode => json!({ "mcpServers": { "ibexwall": {
                "type": "stdio", "command": "ibexwall-mcp", "args": ["--client", name] } } }),
            Self::Opencode => json!({ "mcp": { "ibexwall": {
                "type": "local", "command": ["ibexwall-mcp", "--client", name], "enabled": true } } }),
            Self::Vscode => json!({ "servers": { "ibexwall": {
                "type": "stdio", "command": "ibexwall-mcp", "args": ["--client", name] } } }),
        }
    }
}

/// Only `https://` addresses: a token must never be sent in the clear.
pub fn check_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("the address must start with https://: the token is never sent in the clear")?;
    let host_ok = !rest.is_empty()
        && rest.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'/' | b'[' | b']' | b'_')
        });
    if host_ok && url.len() <= 200 {
        Ok(())
    } else {
        Err("that is not a plain https address".into())
    }
}

/// With `url`: the client reaches `ibexwall-mcp --http` on another machine.
pub fn render_for(client: McpClient, with_proposals: bool, url: Option<&str>) -> String {
    let name = client.name();
    let snippet = match url {
        Some(url) => serde_json::to_string_pretty(&client.remote_snippet(url)),
        None => serde_json::to_string_pretty(&client.snippet()),
    }
    .expect("static json");
    let propose = if with_proposals {
        "\"plan\", \"propose:*\""
    } else {
        "# add \"plan\" and \"propose:system.*\" to let it propose changes"
    };
    let mut out = format!(
        "Connect {name} to IbexWall\n\nPut this in {}:\n\n{snippet}\n",
        client.file()
    );
    if client.name() == "claude-code" {
        match url {
            Some(url) => out.push_str(&format!(
                "\nOr, from a terminal:\n\n  claude mcp add --transport http ibexwall {url} --header \"Authorization: Bearer $IBEXWALL_MCP_TOKEN\"\n"
            )),
            None => out.push_str("\nOr, from a terminal:\n\n  claude mcp add ibexwall -- ibexwall-mcp --client claude-code\n"),
        }
    }
    if let Some(url) = url {
        out.push_str(&format!(
            "\nOver the network ({url}): the traffic is TLS end to end between this client and the server, and the server refuses anything else.\nOn the machine that runs IbexWall:\n\n  ibexwall-mcp tls-init --host <the name clients use> --out /etc/ibexwall/mcp\n  ibexwall-mcp token create --name {name} --client {name} [--secret-stdin to choose your own] [--expires YYYY-MM-DD]\n\nthen set `[http] enabled = true` in /etc/ibexwall/mcp.toml, add the printed [[token]] block, and start `ibexwall-mcp --http` (the ibexwall-mcp.service unit). Put the token in the IBEXWALL_MCP_TOKEN environment variable on the client, and trust the certificate by its SHA-256 fingerprint.\n"
        ));
    }
    out.push_str(
        "\nFirst, let the user that runs the client talk to IbexWall (read, plan and propose only):\n\n  sudo usermod -aG ibexwall-assistants $USER\n\nand log in again. Remove the user from the group to take the access away.\n",
    );
    out.push_str(&format!(
        "\nThen choose what {name} may do in /etc/ibexwall/mcp.toml. A client the file does not name can only read the posture and the findings.\n\n[[client]]\nname = \"{name}\"\nscopes = [\"read:posture\", \"read:findings\", \"read:events:apps\", {propose}]\nrate_limit = \"30/min\"\n"
    ));
    out.push_str(
        "\nWhat you get, whatever the scopes:\n\
         - the assistant cannot apply, approve or revert anything; changes it proposes wait for you (ibexctl proposals list)\n\
         - changes that cannot be rolled back are refused, and every applied change can be undone with ibexctl rollback\n\
         - every call it makes is written to ~/.local/state/ibexwall/mcp-audit.jsonl; check it with ibexwall-mcp --verify-log\n\
         - names, addresses, SSIDs and home folders are replaced by stable pseudonyms before it sees them\n\
         - the model you connect sees what these scopes allow: prefer a local model for anything beyond the posture\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_client_gets_valid_json_naming_itself() {
        for client in [
            McpClient::ClaudeCode,
            McpClient::Opencode,
            McpClient::Vscode,
        ] {
            let text = render_for(client, false, None);
            let start = text.find('{').unwrap();
            let end = text.find("\n}\n").unwrap() + 2;
            let parsed: Value = serde_json::from_str(&text[start..end]).unwrap();
            assert!(parsed.to_string().contains(client.name()));
            assert!(text.contains(&format!("name = \"{}\"", client.name())));
        }
    }

    #[test]
    fn the_remote_form_never_carries_the_token_and_only_speaks_https() {
        for client in [
            McpClient::ClaudeCode,
            McpClient::Opencode,
            McpClient::Vscode,
        ] {
            let text = render_for(client, false, Some("https://mcp.example:8765/mcp"));
            assert!(
                text.contains("https://mcp.example:8765/mcp"),
                "{}",
                client.name()
            );
            assert!(text.contains("IBEXWALL_MCP_TOKEN") || text.contains("ibexwall-token"));
            assert!(!text.contains("ibx_"), "a token is never printed here");
            assert!(
                text.contains("tls-init")
                    && text.contains("token create")
                    && text.contains("end to end")
            );
        }
        assert!(check_url("https://mcp.example:8765/mcp").is_ok());
        for bad in [
            "http://mcp.example/mcp",
            "mcp.example",
            "https://",
            "https://a b/mcp",
            "https://x;y",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn proposals_are_off_unless_asked_for_and_the_guarantees_are_stated() {
        let off = render_for(McpClient::ClaudeCode, false, None);
        assert!(off.contains("# add \"plan\""));
        assert!(!off.contains("\"propose:*\""));
        assert!(render_for(McpClient::ClaudeCode, true, None).contains("\"propose:*\""));
        for promise in [
            "cannot apply, approve or revert",
            "mcp-audit.jsonl",
            "pseudonyms",
            "rolled back",
        ] {
            assert!(off.contains(promise), "{promise}");
        }
    }
}
