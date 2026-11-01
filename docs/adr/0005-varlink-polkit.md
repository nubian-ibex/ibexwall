<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0005: varlink over unix socket with per-method polkit (D-005)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0007, ADR-0014, threat model

## Context

Clients (desktop app, CLI, TUI, web gateway, MCP server, session agent)
talk to the privileged daemon. We need message framing, streaming
(events), named errors, per-method authorization, and identification of
the calling process without a system bus dependency.

## Options considered

- **D-Bus (zbus)**: natural on the desktop, but drags a bus broker into
  the critical path of a security daemon and names/interfaces are a
  poorer fit for our versioned contract style.
- **gRPC**: heavy; HTTP/2 + TLS + protobuf toolchain for local IPC;
  binary schemas complicate the "everything is inspectable JSON" goal.
- **Plain JSON over unix socket (custom)**: full control, but we would
  reinvent framing, error names and streaming.
- **varlink over unix socket**: JSON messages NUL-terminated, `more`/
  `continues` streaming, named errors, interface versioning, systemd
  ecosystem alignment (resolved, systemd uses varlink). Implementation
  cost is small even if we hand-roll the framing over tokio.

## Decision

IPC is varlink over `/run/ibexwall/core.sock` (socket-activated,
`SocketMode=0666`). Authorization is per method via polkit actions
`com.ibexwall.*`; callers are identified with `SO_PEERCRED` plus
`SO_PEERPIDFD` where available (never a bare PID; no TOCTOU). Plugin
sockets are per-plugin under `/run/ibexwall/plugins/<id>.sock`.

The contract source of truth is the Rust types in `ibexwall-proto`;
`cargo xtask schemas` exports JSON Schemas and the IDL, and CI fails on
drift. Interface breaks open a new interface name
(`com.ibexwall.Core2`); within a version changes are additive only.

## Consequences

- Crate maturity risk on `zlink` is contained: a spike decides between
  the crate and ~a few hundred lines of framing (to be recorded in a
  follow-up ADR during F1).
- polkit authorization of a socket-activated server needs care with
  subject resolution (pidfd vs unix-process with start time); spike in
  F1, tracked in the threat model.
- 0666 socket plus per-method polkit means denial-of-service surface
  (unauthenticated connects); mitigations: per-peer limits and audit
  noise are acceptable on single-user desktops, revisited for the web
  gateway.
