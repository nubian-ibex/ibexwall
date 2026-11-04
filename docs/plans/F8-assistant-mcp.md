<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F8: AI assistant (MCP) and the proposal queue

Goal: an AI client can read posture, findings and events and can propose a
change, and can do nothing else. No tool applies, reverts, approves or
changes scopes; every proposal waits for a human with
`com.ibexwall.proposals.decide`. Spec phase F8 and section 4.12; the
maintainer approved the phase on 2026-11-04.

Status: in progress (autonomous mode).

## Milestones

M1 Proposal queue in the core: SQLite table, `ListProposals`,
`CreateProposal`, `DecideProposal` (the F1 guard comes off), polkit
`proposals.create` and `proposals.decide`, events, audit with the client
named, a bound on pending proposals, expiry, and `ibexctl proposals
list|show|approve|reject`. Approving re-plans from the stored patch and
refuses if the operations changed since the human looked.

M2 `ibexwall-mcp` (stdio, no root, runs as the user): protocol, the tools
and resources of 4.12, per-client scopes from `/etc/ibexwall/mcp.toml`
(Appendix F), redaction before every answer, `untrusted` objects, a rate
limit, and an audit line for every call. ADR-0039 explains why the protocol
is implemented here instead of through the `rmcp` crate.

M3 `ibexctl mcp config <client>` for Claude Code, OpenCode and VS Code.

M4 The Assistant screen (mockup 04): proposals with the AI's text marked as
generated, the plan preview, approve and reject, en and pt-BR, axe clean.

M5 The prompt-injection corpus (SSIDs, domains, process names,
justifications) with tests proving no write happens outside a proposal;
scope and redaction tests; a VM end-to-end where a real stdio MCP client
talks to the server as an unprivileged user against the real daemon.

M6 F8 report, STATUS, threat model update, five-distro run.

## Out of scope

Streamable HTTP and OAuth (off by default in the spec; not built here), a
local model (the e2e uses a scripted client, and says so), and any tool that
mutates state.

## Risks

- Redaction that misses a field: it is applied to the whole answer tree at
  one choke point, and tested against a corpus.
- A client that floods: per-client rate limit in the server and a bound on
  pending proposals in the core.
- A proposal that changes between review and approval: approving re-plans
  and compares the operations' digest.
