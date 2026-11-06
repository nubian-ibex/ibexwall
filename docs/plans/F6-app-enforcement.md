<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F6: per-app enforcement + Ask mode (v0.5 beta)

Goal: the verdicts become real. A program the user blocked cannot connect;
an unknown program asks, once, with a scope the user picks; and stopping
the daemon leaves the network open (fail open, by design). Spec phase F6
and section 4.7 (outbound per app).

Status: delivered (report: `docs/reports/F6-report.md`). M5's eBPF-less
fallback became (degraded mode is open and says so).

## Scope decisions

- **Verdicts in eBPF, policy in userspace.** The hooks keep observing,
  but now they consult maps: `cgroup_policy` (cgroup id → verdict),
  `exe_policy` ((dev, inode) → verdict) and `defaults`. Precedence:
  org lock > explicit app rule > profile default (spec 4.7).
- **Ask mode holds the packet, not the connection: NFQUEUE.** The eBPF
  mark selects `ask`; nftables sends the first packet to
  `queue num N bypass` (no listener = accept, so a dead daemon fails
  open); `net.apps` answers from the agent, or the timeout applies the
  default. The alternative (deny and notify, then add a rule) breaks
  QUIC and gives every ask a failed first attempt; decided in the S6-a
  spike, documented in an ADR.
- **Fail open.** Nothing the daemon loads may block traffic on its own:
  no listener on the queue accepts, the eBPF verdict maps default to
  allow, and the daemon stopping (or the loader dying) must leave the
  network open. Verified by test.
- **Loopback stays open; LAN is configurable; IPv6 parity; QUIC and UDP
  through `sendmsg` hooks.**
- **The prompt is a window, not a notification** (spec 4.10):
  `ibexwall --prompt <id>` in Tauri, mockup 05, with scopes (always for
  this app, this destination only, just once) and a visible timeout.
- **Fallback without eBPF/BTF:** socket cgroupv2 rules for known scopes
  plus nfqueue and /proc, a documented degraded mode. Not in the first
  milestone; the UI must say when it is active.
- **Unblocking is a rule change** with snapshot and rollback, like every
  other change. Nothing auto-expires silently.

## Milestones

M1 Verdict maps: extend the eBPF programs (connect4/6, sendmsg4/6) to
consult the maps and, on a block verdict, fail the call; the loader keeps
the maps in sync with the core's decisions. Unit tests of the verdict
logic in Rust; VM tests that a blocked app cannot connect (TCP, UDP,
IPv6) while everything else can.

M2 The `ask` verdict and NFQUEUE: the queue rule in our table (bypass),
the listener in the core, the decision flow with scopes and the timeout
to the default. Spike S6-a decides the mechanics; ADR follows. VM test:
the first connection of an unknown app waits, is answered by the scope
chosen, and the verdict sticks.

M3 Policy and persistence: `net.apps` plugin (profile default, per-app
rules, LAN setting), rules stored with the rollups, org lock respected,
`fail_mode` (open by default, documented).

M4 The prompt window (mockup 05) and the agent's part: scopes, timeout,
no-notification-only path. `ibexctl apps set` completes the CLI.

M5 Fallback without eBPF, degraded-mode UI, and the performance targets
(verdict overhead within the F4 budget).

M6 `--phase f6` in the VM: blocked app cannot TCP/UDP/QUIC/IPv6 while
others can; ask resolves after an answer and falls to the default with no
agent; stopping the daemon leaves the network open; Docker/Podman
coexistence.

## Spikes

- S6-a (decides P-07): NFQUEUE with `bypass` versus deny-and-notify.
  Criteria: does the held packet survive the agent round trip (QUIC
  included)? What does a 1 s timeout do to the first connection? What
  does the queue rule do when nothing listens?
- S6-b: verdict map updates from userspace while connections fly (aya
  map pinning, update cost), and cgroup id reuse.

## Risks

- Holding packets can look like a network outage: the timeout must be
  short, visible, and fail open.
- cgroup ids are reused; exe identity by (dev, inode) misses scripts
  (the interpreter connects, not the script) - documented in F4 and
  unchanged here.
- BPF on the five distros' kernels with more hook types than F4 used:
  the spike runs first on all five.
