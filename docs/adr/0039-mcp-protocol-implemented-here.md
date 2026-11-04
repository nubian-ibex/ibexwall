<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0039: The MCP stdio protocol is implemented in `ibexwall-mcp`

Status: accepted (autonomous mode, 2026-11-04); the maintainer may reverse
it. Phase: F8.

## Context

The spec names the `rmcp` crate for the MCP server. `rmcp` 3.8 is available
and Apache-2.0; its server side is built around procedural macros and a
large dependency set that also carries the HTTP and OAuth stacks this server
leaves off.

## Decision

The stdio transport and the handful of MCP methods the server needs
(`initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`,
`resources/templates/list`, `resources/read`, the `initialized`
notification) are implemented in the crate: newline-delimited JSON-RPC 2.0,
about 400 lines, pure functions over `serde_json::Value`, covered by tests
that include malformed and hostile input. The protocol version is negotiated
by echoing a supported client version.

## Why

- Every byte the assistant can cause is visible in one place: a tool that
  does not exist in the list cannot be called, and the list is a constant.
- No macro-generated handlers, no HTTP or OAuth code compiled into a binary
  that must stay minimal.
- The fuzz and prompt-injection tests drive the same pure functions the
  server runs.

## Consequences

- Streamable HTTP and OAuth are not available until someone builds them; the
  spec keeps them off by default.
- Protocol drift is ours to follow. If more of MCP is needed later (prompts,
  sampling), switching to `rmcp` behind the same tool functions is a local
  change.
