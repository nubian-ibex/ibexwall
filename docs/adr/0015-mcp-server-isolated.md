<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0015: MCP assistant as an isolated, powerless client (D-015)

- Status: Accepted
- Date: 2026-11-01

## Context

AI assistants are useful for posture triage but must never become an
unattended privileged actor, and prompt injection through untrusted
data is a real channel.

## Decision

`ibexwall-mcp` is a separate rootless binary speaking the same varlink
API as any client. Read/dry-run tools only; changes go through the
human approval queue as proposals. Sensitive plugins are denied by
default; responses are redacted (stable pseudonyms for user, hostname,
SSID, MAC, private IPs). Untrusted fields travel in a structured
`untrusted` object.

## Consequences

- The MCP surface is auditable and testable (prompt-injection corpus,
  scope tests).
- Local-model-first guidance with explicit warnings for remote
  providers.
