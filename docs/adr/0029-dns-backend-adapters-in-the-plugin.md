<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0029: DNS backend adapters live in the net.dns plugin

Status: accepted (F3, 2026-11-02). Deviation from spec section 4.8, which
describes backends as adapters driven by a `dns.backend` operation.

## Context

The spec lists four integration backends (resolved + NetworkManager,
resolved + networkd, NetworkManager alone, resolv.conf hooks) and a typed
`dns.backend` operation. The change engine already snapshots and rolls back
`file.write` and `systemd.unit` byte for byte, and those are what every
backend ultimately does.

## Options

1. Implement `dns.backend` in the core: one more executor and one more
   inverse, with backend knowledge in the privileged side.
2. Detect the stack in the plugin (read-only) and propose `file.write` and
   `systemd.unit` operations (chosen). The privileged side keeps one small,
   tested vocabulary; each backend is a plugin function tested against a
   tree fixture and, in VM, on its own distro.

## Decision

Option 2. `dns.backend` stays reserved and validate-only. The plugin refuses
a stack it does not support instead of guessing.

## Findings that shaped the implementation (VM, five distros)

- With `DNS=127.0.0.153`, `Domains=~.` and `FallbackDNS=` (empty) in the
  resolved drop-in, a packet capture shows no clear DNS leaving the machine
  on Fedora, Ubuntu 24.04, Ubuntu 26.04, Debian and Arch, while the link
  still advertises its own DHCP server with `+DefaultRoute`. The global
  routing domain wins; only DoT to the chosen upstream is seen.
  `FallbackDNS=` is an addition to the spec's two keys: without it a dead
  local resolver would make resolved fall back to plain public servers.
- This was measured on each distro's default cloud-image network stack; the
  NetworkManager drop-in the spec mentions was not needed and is not
  written until a case shows it is.
- A transaction that restarts a unit must restart it again after rollback
  restores the files it reads; the engine now does this in a second pass.
- `systemctl is-enabled` prints the state but exits non-zero for every state
  other than enabled. Snapshots were reading "disabled" as "not found", so
  rollback never disabled a unit that was off before (F1 defect, found by
  the f3 rollback scenario, fixed with a parser test).
- When the resolver cannot stay up (three failures in 60 s),
  `ibexwall-dns-failsafe.service` removes only IbexWall's drop-in and
  restarts resolved; DNS works again within seconds. The failsafe also
  clears resolved's start rate limit first: a burst of transaction
  restarts can trip it and the failsafe would otherwise fail exactly when
  it is needed (found by the VM kill scenario).
- Browser DoH steering is one known file per browser with exactly the
  vendor-documented disable-DoH policy (sources cited in
  `ibexwall-sys/src/browser.rs`), proposed only for installed browsers and
  only with explicit consent; Firefox's fixed-name policies.json is never
  overwritten when an administrator already manages it.
- The known-DoH-endpoints list (HaGeZi's Encrypted DNS Bypass, 3505
  entries) is loaded through the same block-list machinery when the
  browser-bypass block is on, so applications cannot route around the stub
  by speaking DoH to a public server on port 443.
- Provider presets ship only with vendor-verified facts. Mullvad was
  evaluated and rejected: its public encrypted DNS service is
  discontinued as of 2026-11-02.

## Consequences

- Backends B2 (resolved + networkd with `UseDNS=`) and B3/B4 (no resolved)
  are separate plugin adapters still to be written and tested; until then
  the plugin returns an explicit "not supported yet" for those stacks.
- The per-link DNS of a VPN client that sets its own routing domains can
  still win for those domains; this is listed as a "may affect" item.
