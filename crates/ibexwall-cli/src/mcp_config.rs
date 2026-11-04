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

pub fn render(client: McpClient, with_proposals: bool) -> String {
    let name = client.name();
    let snippet = serde_json::to_string_pretty(&client.snippet()).expect("static json");
    let propose = if with_proposals {
        "\"plan\", \"propose:*\""
    } else {
        "# add \"plan\" and \"propose:system-*\" to let it propose changes"
    };
    let mut out = format!(
        "Connect {name} to IbexWall\n\nPut this in {}:\n\n{snippet}\n",
        client.file()
    );
    if client.name() == "claude-code" {
        out.push_str("\nOr, from a terminal:\n\n  claude mcp add ibexwall -- ibexwall-mcp --client claude-code\n");
    }
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
            let text = render(client, false);
            let start = text.find('{').unwrap();
            let end = text.find("\n}\n").unwrap() + 2;
            let parsed: Value = serde_json::from_str(&text[start..end]).unwrap();
            assert!(parsed.to_string().contains(client.name()));
            assert!(text.contains(&format!("name = \"{}\"", client.name())));
        }
    }

    #[test]
    fn proposals_are_off_unless_asked_for_and_the_guarantees_are_stated() {
        let off = render(McpClient::ClaudeCode, false);
        assert!(off.contains("# add \"plan\""));
        assert!(!off.contains("\"propose:*\""));
        assert!(render(McpClient::ClaudeCode, true).contains("\"propose:*\""));
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
