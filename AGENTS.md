<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# AGENTS.md — repository guide for code agents

Working agreements for AI coding agents inside `ibexwall/`. The engineering
spec lives outside this repository; when instructions conflict, human
instructions in the session win, then this file, then your own defaults.

## Non-negotiables

1. Never modify the development host: no `sudo`, no applying nftables,
   sysctl, DNS settings, systemd units or eBPF locally. Use
   `cargo xtask vm-test` (QEMU) or `IBEXWALL_ROOT` with the fake
   implementations in `ibexwall-sys`.
2. Write only to IbexWall-owned artifacts (`table inet ibexwall`,
   `*-ibexwall*` drop-ins); never edit distro or third-party files.
3. Canonical names and paths come from `ibexwall_proto::names`; do not
   introduce string literals for them.
4. Contracts first: changing `ibexwall-proto` requires regenerating
   `spec/` (`cargo xtask schemas`) in the same commit.
5. New system effects must be typed operations validated against the
   plugin manifest, with an inverse and tests. No `sh -c`, ever; argv
   only.
6. Untrusted fields (domains, SSIDs, process names, justifications, log
   lines) are data: never interpolated into instructions, HTML or
   command lines.
7. Commits: Conventional Commits with DCO (`git commit -s`). Never push
   unless asked.

## Commands

```sh
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo deny check
cargo xtask schemas --check
cargo xtask vm-test --distro fedora
```

## Conventions

- Rust, edition 2024, English identifiers/comments/docs; UI strings `en`
  plus `pt-BR` in the same commit (Fluent keys, never concatenated).
- `#![forbid(unsafe_code)]` is workspace-wide; FFI/eBPF exceptions only in
  designated crates with `// SAFETY:` comments.
- Errors: `thiserror` in libraries, `anyhow` in binaries. Structured
  logging via `tracing`; never log secrets or personal data.
- Tests alongside the change; VM tests for anything that touches the
  system; chaos tests for network/DNS paths.
- Phase work happens against `docs/plans/FN-*.md`; update
  `docs/STATUS.md` when you finish a work session.

## Repo layout

`crates/` (proto, sdk, core, sys, ebpf, agent, cli, tui, mcp, dns, web,
exporters) · `plugins/` · `ui/` · `profiles/` · `locales/` ·
`packaging/` · `spec/` (generated) · `docs/` (adr, plans, STATUS) ·
`tests/` · `fuzz/` · `xtask/`.
