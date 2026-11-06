<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F8 report: AI assistant (MCP) and the proposal queue

Date: 2026-11-04. Plan: `docs/plans/F8-assistant-mcp.md`. ADR: 0039 (the MCP
stdio protocol is implemented in the crate; reversible by the maintainer).

## What was done

- Core: a proposal queue. `CreateProposal` plans the change at once, so the
  person reviews the real operations; `DecideProposal` approves (plans again
  from the stored patch and applies only if the operations are the ones that
  were reviewed, else `ProposalStale`) or rejects. Bounded (20 pending, 8 per
  client), expires after a day, justification stripped of control
  characters. A plan that cannot be rolled back is refused at proposal time.
  `ListAudit` exposes the rows of the hash-chained audit log, which now name
  the assistant (`mcp:<client>`) for what it proposed. `ibexctl proposals
  list|show|approve|reject`; `show` fences the AI's text as untrusted.
- `ibexwall-mcp` (stdio, runs as the user, no root): the nine tools of the
  spec and the resources `posture`, `report`, `findings/{plugin}`,
  `events/{source}`, `config/{plugin}` and `audit/changes`. There is no tool
  to apply, revert, approve or change a scope or a policy, and a test asserts
  the list is exactly the nine.
- `ibexctl mcp config <client>` for Claude Code, OpenCode and VS Code: the
  snippet to paste, the matching `mcp.toml` stanza (read-only unless
  `--with-proposals`) and the guarantees below. It needs no daemon.
- The Assistant screen (mockup 04): proposals waiting for a person, the AI's
  words in a quote marked "written by the AI, not checked", the operations
  and what they may affect, Approve and Reject, a clear message when the plan
  changed. English and Portuguese, axe clean in both themes.

## The guarantees, and what enforces each

What the assistant can do is bounded by the server and, behind it, by the
core and polkit, so a client that bypasses the server gains nothing.

- It cannot apply, approve or revert. Not in the tool list (tested), and the
  user that runs the assistant is not allowed `apply`, `rollback`,
  `plugins.manage` or `proposals.decide` by polkit (VM: those commands run as
  that user fail, and the system is unchanged).
- Everything it does is logged, before it happens. Each call writes a `call`
  line to `~/.local/state/ibexwall/mcp-audit.jsonl` (0600) before any work,
  and a `result` line after. If the first line cannot be written the call is
  refused. Each line carries the SHA-256 of the previous one:
  `ibexwall-mcp --verify-log` finds a removed or edited line (VM: a deleted
  line is detected). Denied calls and a flood (one line, not thousands) are
  logged too. Parameters are logged after redaction and cut to 2000
  characters.
- The core keeps its own chain. A proposal, its approval and its rejection
  are rows in the core's audit chain with the client named; `ibexctl audit
  verify` checks it, and the `audit/changes` resource tells the assistant
  which changes were its own.
- Rollback is guaranteed for what it proposes. A proposal whose plan is
  irreversible is refused; every proposal shows `reversible`, the risk flags
  and whether a confirmation window applies; an approved change is
  snapshotted by the engine and `ibexctl rollback` restores it (VM: kernel
  value back to its prior state, the drop-in gone).
- The person sees the real thing. The plan is made when the proposal is
  created and again at approval; if the operations differ the approval is
  refused.
- Reports are the focus. `get_posture`, `list_findings`, `explain_finding`,
  `query_events`, `get_app_connections`, `run_check` and the `report`
  resource are read-only; `dry_run` shows what a patch would do and queues
  nothing (VM: the system and the queue are unchanged afterwards).
- External text is data. Finding arguments, event fields, destinations and
  the assistant's own justification are returned under `untrusted`; every
  tool description says so. Private values are pseudonyms (user, host, SSID,
  MAC, private IP; homes become `~`) from an HMAC under a local 0600 salt,
  applied at one point to the whole answer, errors included.
- Scopes come from `/etc/ibexwall/mcp.toml`; a client the file does not name
  can only read posture and findings, at 30 calls a minute. System accounts,
  disks and managed devices are closed to every client, and also removed from
  answers that mention them. DNS history is counts only unless the owner
  says otherwise.

## How it was verified

- 500 workspace tests (39 in `ibexwall-mcp`), clippy, fmt, deny and schemas
  clean; 91 UI tests and the e2e suite (including axe in both themes and
  languages).
- Prompt-injection corpus (12 payloads: instructions, forged JSON-RPC,
  embedded newlines, tag spoofing, terminal escapes, bidi text, shell and
  SQL): through every read tool the payload appears only under `untrusted`,
  every answer is one JSON-RPC line, the core only sees reads, and hostile
  arguments are rejected before reaching the core. The corpus found two real
  leaks on its first run (`list_proposals` and the audit view returned text
  outside `untrusted`); both are fixed and the corpus stays in the suite.
- `cargo xtask vm-test --phase f8` on fedora, ubuntu-24.04, ubuntu-26.04,
  debian and arch, four scenarios each: the surface and the refusals; a
  proposal that waits, is refused to the assistant's own user, approved by a
  person and rolled back; both logs, including tamper detection; hostile
  text that stays pending text.
- Regressions f1, f3, f4, f5, f6 and f7 re-run green on fedora after the
  core changes (proposal fields, `ListAudit`).

## Honest limits

- The end-to-end uses a scripted client, not a language model. It sends
  fixed requests, hostile ones included, to the real server and the real
  daemon. What a given model does with the text it reads is not tested; the
  design makes that irrelevant for writes (a model that is fully convinced
  can still only create a proposal a person must approve) but it can still
  be misled in what it says to the person. Real-client smoke tests with
  Claude Code, OpenCode and VS Code are part of the manual runs the
  maintainer deferred.
- The assistant's log is a file in the user's own directory. The same user
  (or malware running as them) can delete the whole file; the chain detects
  edits and removals in the middle, not a log that is gone or cut at the end.
  The core's chain in `/var/lib/ibexwall` is out of that user's reach.
- Whatever the scopes allow is sent to the model you connect. The config
  command says to prefer a local model beyond the posture; redaction lowers
  the risk, it does not make remote models private.
- The rate limit is per server process; a client that starts many processes
  is bounded by the core's pending-proposal limits instead.
- `get_app_connections` ignores `since` (the monitor keeps aggregates), and
  says so in its answer.
- Streamable HTTP was built after acceptance (see "After acceptance"); OAuth
  was not (decision 2026-11-04: a user-defined Bearer token instead).
- Access for the user that runs an assistant is the group
  `ibexwall-assistants` (created by `packaging/sysusers.d/ibexwall.conf`),
  with the packaged polkit rule `49-ibexwall-assistants.rules` granting only
  read, plan and `proposals.create`. The VM test installs both as shipped and
  checks that a user outside the group cannot even read.

## Decisions for the maintainer

- (own MCP protocol instead of `rmcp`) was taken in autonomous
  mode; it is local and reversible.
- Accepted 2026-11-04: access through a packaged polkit rule for the group
  `ibexwall-assistants` (done), `ibexctl mcp config` tells people to join it.

## After acceptance: the HTTPS transport (2026-11-04)

Built at the maintainer's request, with a key or token the user defines.

- `ibexwall-mcp --http`: Streamable HTTP (MCP 2025-06-18), TLS only (no plain
  mode exists), off unless `[http] enabled = true` in `/etc/ibexwall/mcp.toml`.
- Access is a Bearer token `ibx_<id>_<secret>`. The person lets IbexWall
  generate 256 random bits or chooses their own secret (24 characters or
  more, varied, read from stdin so it never touches argv), names it, binds it
  to a `[[client]]` (its scopes), and may set an expiry. Only an Argon2id hash
  is written. `ibexwall-mcp token create` and `tls-init` print what to paste;
  nothing edits `/etc`.
- The door: `Origin` allow list (empty by default), failed sign-ins counted per
  address (429 past a limit), bounded headers and bodies, timeouts, a
  connection cap, a decoy hash for unknown ids.
- Behind the door it is the same pipeline as stdio, over one shared audit chain
  that records `via: http:<token id>`.
- `ibexctl mcp config <client> --url https://HOST:PORT/mcp` prints the remote
  form for Claude Code, OpenCode and VS Code; the token comes from the
  environment or a prompt, and an `http://` address is refused.
- The unit `ibexwall-mcp.service` runs as `ibexwall-mcp` in the assistants
  group (systemd exposure 1.7).
- Verified on five distros (VM scenario h5): generated and chosen tokens
  work, a scope the client lacks is refused over HTTP, wrong, expired and
  missing tokens and a foreign origin are refused, GET is refused, plain HTTP
  and an unverified certificate fail, and the log names the token, verifies
  and holds no secret (neither does the journal).
- Limits: a stolen token works until it is removed or expires; a self-signed
  certificate is only as good as the fingerprint check on the client; a
  TLS-terminating proxy in front would end the end-to-end property.
