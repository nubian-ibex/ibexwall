<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0032: the core supervises the eBPF loader as a child process

Status: accepted (2026-11-03). Phase: F4.

## Context

The connection monitor needs `CAP_BPF`/`CAP_PERFMON` and aya, and its
events must reach the rollups and the event bus. Options: (a) load eBPF
inside `ibexwalld`; (b) a separate service talking to the core over
varlink; (c) the core spawns the loader and reads its stdout.

## Decision

(c). `ibexwalld` spawns `ibexwall-ebpf-loader`, which prints one JSON
object per connection; the core parses, correlates with the resolver's
answers, rolls up and raises events. A loader that exits is restarted
with exponential backoff (2 s up to 60 s, reset after a healthy minute);
`ListApps` reports `monitor.running` and the reason when it is off.

## Why

- aya and the BPF capabilities stay in a small, separately hardenable
  binary; a parser bug in the core never runs with BPF in the same
  address space.
- No new socket, no new polkit action: the child's stdout is the only
  channel and it is not reachable by other users.
- The core stays testable: tests use a fake child that prints JSON lines.
- Every field of a line is untrusted data (process names and paths):
  parsed into typed fields, stored with bound parameters, never run.

## Consequences

- The sandbox root never starts the loader (no eBPF on the dev host).
- Loopback and unspecified destinations are not recorded: they are local
  plumbing, not network traffic.
- Alerts are events (`apps.first_connection`, `apps.binary_changed`);
  turning the binary-changed alert into a finding with remediation
  comes with the Apps screen.
- A resolver-to-core channel for IP-to-domain answers is still to be
  built; until then destinations show as addresses (`resolved=false`).
