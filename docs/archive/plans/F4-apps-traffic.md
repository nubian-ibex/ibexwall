<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F4: apps and traffic (monitor)

Goal: know which program talks to which domain, in monitor mode only.
Identity per spec section 4.9, connection events via eBPF, correlation
with the DNS map from `net.dns`, per-app rollups, first-connection alerts
and a changed-binary alert, and the Flatpak block via `flatpak.override`.
The Apps and network screen shows the modes; only Monitor and
Block-Flatpak are functional. Spec phase F4.

Status: in progress (autonomous mode).

Progress:
- S4-a done: the connect monitor loads, attaches and
  attributes on all five distros; ring-buffer wake-on-event; overhead
  bounded (< 3 us per connect in the hook, < 20 us per event in the
  loader); `cargo xtask ebpf` builds the ELF outside the workspace.
- M1 (kernel-side identity) done: a `sched_process_exec` tracepoint fills
  an LRU pid-to-exec-path map; the connect hook copies the path into the
  event (128 bytes), so processes that exit before userspace reads
  `/proc` stay attributable. Pass on the five distros.
- M1 identity done: `ibexwall-identity` classifies cgroups per spec 4.9
  (Flatpak, Snap, desktop `app-*` units with `\x2d` unescaping, system
  services, containers, CLI sessions), hashes executables (SHA-256) and
  asks rpm, dpkg or pacman for the owning package through an allowlisted
  argv runner. The loader enriches events with kind, id, hash and package
  (cached per exe). Verified on the five distros (curl is a `cli`
  owned by `curl`). Origin and signature status come with M3.
- M3 done: `ibexwall-apps` (correlator, rollups, alerts),
  migration 0003, `ibexwall-monitor.service` (own hardened unit) feeding
  the core over a root-only socket, the resolver reporting answers over a
  datagram socket for IP-to-domain, `ListApps` and `GetAppDestinations`
  in the contract, events for first connection and changed binary. The
  hardened unit passes on the five distros (Debian degrades: no kernel
  exec capture, documented).
- M4 done: `flatpak.override` executor, `apps.flatpak-network`
  plugin, byte-for-byte rollback; the real Flatpak reads the file and
  the VM scenario proves apply, read-back and rollback on the five
  distros. Snap via interface is still to do.
- M5 CLI done: `ibexctl apps list|info` (terminal-safe output). M6
  partly done: `--phase f4` proves, through the real core and the real
  monitor unit, attribution of curl (package), a system service, a
  Flatpak scope, a Podman container and a snap (Ubuntu), plus domain
  correlation over the resolver socket; found and fixed a hook that
  returned 0 and blocked connects. Still open:
  Firefox as a package, the GUI Apps screen, the TUI apps view.
- Overhead measured against the spec criterion (hook plus loader CPU
  per connection, non-loopback destinations, best of five): fedora 1.26%,
  debian 1.04%, ubuntu-24.04 0.92%, arch 0.88%, ubuntu-26.04 0.65% of one
  CPU at 1000 connections/s (target below 2%). The loader reads cgroups
  from an in-memory index first.
- M5 GUI done: Apps and network screen (mockup 02) with the four modes
  shown (Monitor everywhere, Block only for Flatpak apps), search,
  Connected now and New filters, destinations with "no domain known"
  marking, the Flatpak block through the shared change flow; en and
  pt-BR, axe clean in both themes, keyboard navigation updated. Shows
  only what is measured (counts, times, package): no bytes or countries.
- The `--phase f4` spike scenarios (attribution with asymmetric v4 and
  v6 destinations, overhead) pass 2/2 on the five distros.

## Scope decisions

- **Monitor only.** No verdicts, no blocking of traffic by app (that is
  F6). eBPF attaches to tracepoints/LSM-less hooks that observe
  connect() events and exit through a ring buffer; nothing is dropped.
- **Identity is best effort and labelled.** The systemd scope/unit name,
  cgroup path and `/proc` give kind and id; interpreters are recorded as
  the script path with a documented limitation. Unknown is a valid state.
- **Correlation is time based.** The resolver keeps a short-lived IP to
  (domain, TTL) map (spec section 4.8) and the monitor joins on it;
  misses are recorded as unresolved, never guessed.
- **Privacy.** Domains and identities stay local; rollups keep counts and
  last-seen only. The query log stays off unless the user turns it on.
- **Flatpak blocking goes through the typed op.** `flatpak.override` is
  executed by the core with snapshot and rollback; the plugin never runs
  flatpak itself.

## Milestones

M1 Identity (`ibexwall-identity` or inside the loader crate)
- Map cgroup/scope/unit names to `{kind, id}` per the spec table.
- exe path, SHA-256 and owning package (`rpm -qf`, `dpkg -S`, `pacman -Qo`)
  via typed exec allowlist entries; origin from the package manager.
- Tests with fixture trees; interpreters documented.

M2 eBPF monitor
- aya program(s): connect events (IPv4 and IPv6) with pid, cgroup id,
  destination; ring buffer to the loader; cgroup accounting.
- Loader crate: verify BTF/CO-RE, attach, read events, graceful
  degradation when the kernel lacks a feature (monitor off, UI says so).
- No capabilities beyond what the unit needs (`CAP_BPF`,
  `CAP_PERFMON` or root, documented); unit hardened like the others.
- VM first: all five distros, measure overhead at 1k conn/s (< 2% CPU).

M3 Correlation and rollups
- IP to domain map from the resolver (shared struct, TTL aware).
- Per-app rollups in SQLite: counts per domain per app, first seen, last
  seen; retention by the spec's data policy.
- First connection for an app and changed-binary alerts as findings.

M4 `apps.flatpak-network` + `flatpak.override`
- Check: Flatpak overrides present per app (list from `flatpak list`).
- Plan/apply/rollback of `--unshare=network` style overrides via the
  typed op; consent and may-affect in the manifest.

M5 Apps and network screen (mockup 02)
- List of apps with domains and counts, monitor status, modes shown with
  the ones that work; en and pt-BR, a11y, both themes.
- TUI: apps view.

M6 VM phase `--phase f4`
- Attribution proven for Firefox (package), a Flatpak app, Snap on
  Ubuntu, curl in a terminal, a systemd service and a container.
- Overhead measurement; Flatpak block applies and reverts.

## Spikes

- S4-a: done.
- S4-b (M3, 1 day): cgroup id to path resolution cost; caching strategy.
- S4-c (M4, 0.5 day): `flatpak override` behavior and file layout per
  distro (verification against Flatpak's own docs).

## Risks

- eBPF portability across the five distros' kernels; mitigate with CO-RE
  and per-kernel probes, monitor off when unsupported, and the spike
  before any UI work.
- Perf: ring buffer backpressure; drop policy is "count drops, never
  block the host".
- Snap confinement limits what `/proc` shows; label as best effort.

## Definition of done

Section 17 of the spec plus: attribution proven in VM for the six cases,
overhead under target, Flatpak block reversible byte for byte, ADRs for
the spike outcomes, phase report, updated STATUS.
