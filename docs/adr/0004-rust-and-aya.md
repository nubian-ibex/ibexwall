<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0004: Rust for the whole client, eBPF with aya (D-004)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0005, ADR-0007, ADR-0013

## Context

The product is a privileged daemon orchestrating nftables, eBPF, systemd
and D-Bus on desktop Linux, plus CLI/TUI/desktop clients and a plugin SDK
exposed to third parties. Language choice drives memory safety, eBPF
toolchain maturity, hiring pool and the SDK story.

## Options considered

- **C**: deepest systems integration, but memory-unsafe daemon root on
  endpoints is exactly the risk class we exist to reduce.
- **C++**: same safety concerns plus a fragmented dependency story.
- **Go**: great concurrency and tooling; weak fit for single-file
  deployed daemons (runtime bundling), no first-class eBPF CO-RE story,
  larger memory footprint for an always-on desktop daemon.
- **V**: young ecosystem, no established eBPF story; rejected during
  planning.
- **Rust**: memory safety without GC, tokio ecosystem, aya for eBPF with
  CO-RE, zbus for D-Bus, excellent CLI/TUI crates; one language across
  daemon, plugins, CLI, TUI and MCP server.

## Decision

Write the whole client in Rust (edition 2024). eBPF programs use aya +
aya-ebpf with CO-RE; nightly is pinned only to build eBPF, everything
else stays on stable.

## Consequences

- One toolchain and one review skill set across the codebase.
- aya is younger than libbpf; verifier quirks surface as issues we own.
  Mitigation: kernel test matrix (virtme-ng) and deliberately simple
  programs, plus a documented degraded mode without eBPF.
- The plugin SDK is Rust-first; bindings for other languages come after
  v1 (spec §"after v1").
