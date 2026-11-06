<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F6 report: per-app enforcement and Ask mode

Date: 2026-11-03. Plan: `docs/plans/F6-app-enforcement.md`. ADRs: 0035
(Ask holds the first packet in NFQUEUE, resolves P-07), 0036 (Ask driven by
the core), 0037 (no eBPF means no enforcement, and the UI says so).

## What was done

- Verdicts in the kernel. The connect and sendmsg hooks (IPv4 and IPv6)
  consult maps: a rule on the cgroup (Flatpak scopes, containers, services),
  else a rule on the executable path the exec tracepoint recorded (matched
  inside the hook, so there is no race at a process's first connect), else
  the default. Block fails the call with EPERM; everything else, absent or
  failing, allows. `sendmsg4/6` decide for UDP without `connect` (DNS,
  QUIC) and record nothing.
- Policy in userspace. `ibexwall-apps::policy` stores the modes (allow,
  monitor, ask, block) per app and per destination in SQLite (migration
  0004) and builds the rules from them (only what differs from the default;
  a cgroup-matched app keeps an explicit allow so it shadows a program-wide
  block; an organization lock layer is in the builder). The loader's
  `Enforcer` owns the verdict maps, applies each policy the core pushes
  over the monitor socket (now bidirectional), refuses invalid ones keeping
  the previous, clears stale entries, and rescans cgroups every two seconds
  only while cgroup rules exist.
- Ask. The hook marks the flow's socket and records who made it; nftables
  queues the first packet of a marked new flow to queue 4242 with `bypass`;
  the loader (a netlink NFQUEUE client over `rustix`, no C library, no
  unsafe) holds it, sends the question to the core and releases it with the
  answer, or releases it accepted with a mark that a later chain rejects.
  The core keeps the open questions, coalesces retransmissions, remembers
  per-destination answers, and installs the queue and refuse chains only
  while something is in Ask mode.
- Clients. `ibexctl apps set|default`, `ibexctl prompts list|answer`; the
  Apps screen sets the four modes for real; the prompt (mockup 05) is a card
  with the app, destination, scopes (always, this destination, only this
  time), Block and Allow, and a live countdown, floating over the main window
  or alone in `ibexwall --prompt`; the agent announces a question as an
  urgent notification whose click opens that window; the TUI Apps tab shows
  the mode, moves a cursor, sets modes with 1 to 4 and answers with y or b.
  All strings in en and pt-BR; axe clean on both themes and locales.
- Ingestion at volume. The core records connections in batches of up to
  1024 per transaction (a commit per connection capped it near 30 a second),
  and the eBPF ring buffer grew from 16 KiB to 1 MiB.

## How it was verified

- 374 workspace tests, clippy, fmt, deny and schemas clean; 82 UI tests and
  19 e2e (axe on both themes and locales, including the dialog).
- `cargo xtask vm-test --phase f6` on fedora, ubuntu-24.04, ubuntu-26.04,
  debian and arch, 8 scenarios each:
  - v0: a copy of python under a blocked path is refused over TCP, UDP with
    and without connect, a QUIC port and IPv6, while the original python
    and the resolver still work; the refusal is immediate.
  - v1: stopping the monitor leaves the network open.
  - a0: Ask without the core: held for the asked time, then connected or
    refused; with no listener on the queue the connection goes through at
    once (0 ms).
  - m3: through the packaged core and unit, `ibexctl apps set` blocks a
    service (cgroup) and a program (path, where the kernel allows) and
    reopens them without a restart; stopping the unit fails open and
    starting it restores the block; the choice survives a core restart.
  - m4: Ask through the core: held until answered (2.1 to 2.2 s measured),
    refused, a remembered destination is not asked again, unanswered
    questions are released open after the 30 s timeout (30.04 s), "always
    block" changes the mode, the nft chains disappear with the last Ask app,
    and stopping the daemon completes the held connection in about 1 s.
  - c0: real Docker and Podman containers: blocking one container's mode
    does not touch the other runtime's, the Ask chains do not break either,
    and the nftables ruleset outside our table is identical before and after.
  - p0: 5000 connections a second for four seconds, every one recorded
    (20001 of 20001 on four distros, 19999 of 19999 on one); core idle RSS
    9 MB (target 40), core 12 to 15% and loader 7 to 8% of one CPU during
    the storm. F4's regression (overhead 1.2 to 1.5% of one CPU at 1000
    connections a second) still passes.
- Regressions f4 and f5 re-run green on fedora after the core and hook
  changes.

## Defects found and fixed along the way

- A 98-byte copy of an exe rule overflowed the 512-byte eBPF stack on
  Ubuntu 24.04's verifier; rules are now matched in place.
- The kernel's NFQUEUE configuration attribute for the flag mask is 4, not 6
  (the queue refused to bind).
- A `queue` verdict resumes at the next hook entry, not the next rule: the
  refusal lives in a chain with a higher priority number.
- The core recorded each connection in its own transaction, so a burst
  backed up until the loader's write timed out; batching fixed it.
- A loader that lost the core kept enforcing until its next write failed;
  it now exits at once, which opens the network and lets systemd bring it
  back with the core's policy.

## Deviations and open points (decided 2026-11-03)

- the Ask chains are derived state reconciled by the core, not a
  plugin proposal through plan, approval and rollback; the mode change the
  user makes is the approval and the rollback. If you prefer the strict
  path, they move into a built-in plugin at the cost of an approval prompt
  the first time an app is put in Ask mode. The monitor unit now may open
  netlink sockets (`AF_NETLINK`) for the queue.
- the nft `socket cgroupv2` fallback for machines without eBPF was
  not built; degraded mode is "open, and the UI says why". It could only
  cover system services, not Flatpak scopes or containers.
- Spec naming: several plugin ids in the spec use `_`
  (`apps.flatpak_perms`, `system.session_lock`, `privacy.camera_mic`) while
  the manifest rule is `[a-z0-9-]`. Please pick one; `apps.flatpak_perms`
  stays reserved for the F7 audit plugin.
- The prompt's default scope is "only this time" (the mockup preselects
  "always"): a slip of the mouse must not become a permanent rule.
- Ask cannot hold a container's connections (they leave through another
  network namespace, where the queue rule does not run): the UI and
  `SetAppMode` offer allow, monitor and block for containers only.
- Unconnected UDP (`sendto`) is blocked by the verdict but not held in Ask
  mode.
- A cgroup created after a policy (an app launched after the rule) has up to
  two seconds of grace before its cgroup rule applies; an event-driven
  rescan (a raw tracepoint on cgroup creation) would close it.
- Debian's `perf_event_paranoid=3` withholds the exec tracepoint from the
  hardened unit, so rules on a program's path are unavailable there (the
  monitor says so, the UI disables them with the reason); rules on
  services, Flatpaks, snaps and containers work. A `tp_btf` attach, which
  needs no `perf_event_open`, is the likely fix.
- App keys for containers read `container:container:<id>` (the identity
  already carries the kind); harmless, but untidy.
- Not done here: org lock source (the builder takes it), `fail_mode` as a
  user setting (open is the only mode; timeout and fallback are stored
  settings with defaults but have no UI), the LAN setting, and the manual
  runs on Omarchy and EndeavourOS.
