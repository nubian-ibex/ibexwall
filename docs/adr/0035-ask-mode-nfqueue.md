<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0035: Ask mode holds the first packet in NFQUEUE

Status: accepted (spike S6-a, 2026-11-03, five distros). Resolves P-07.
Phase: F6.

## Context

An app in Ask mode must wait for the user's answer without breaking the
connection. Options: (a) deny the first attempt, notify, and add a rule
after the answer; (b) hold the first packet in an NFQUEUE and release it
with the answer.

## Decision

(b). The eBPF connect hook, on an `ask` verdict, records `flow id -> (pid,
cgroup)` in a map and sets the socket mark to `0x01xxxx` (the id in the
low 16 bits, the byte above the mask left as the application had it).
nftables queues the first packet of a new marked flow to queue 4242 with
`bypass`; the loader binds the queue, finds the flow by the mark, waits
for the answer and releases the packet. A refusal accepts the packet with
the mark `0x02xxxx`, which a later chain rejects (reset or ICMP), so the
application fails at once instead of hanging.

## Findings (fedora, ubuntu-24.04, ubuntu-26.04, debian, arch)

- Held for exactly the configured time, then the connection completes
  (2000 ms asked, 2000 ms measured); a refused flow is reset after its wait
  (1000 ms); a program not in Ask mode is not slowed.
- With no listener on the queue, `queue ... bypass` accepts at once (0 ms):
  Ask fails open, like everything else the daemon does.
- A `queue` verdict resumes at the next hook entry, not the next rule of
  the same chain, so the refusal rule lives in a chain with a higher
  priority number.
- The kernel's configuration attributes are `MASK = 4`, `FLAGS = 5`; the
  queue is configured fail-open and bounded.
- The client is netlink by hand over `rustix` (no libnetfilter_queue to
  install, no unsafe code); message building and parsing are unit tested.

## Consequences

- UX: no failed first attempt, QUIC and TCP alike.
- Applications that set their own SO_MARK before connecting lose the low
  24 bits for Ask flows (VPN daemons are not user apps in Ask mode); the
  high byte is preserved.
- Only connect-time marking is in this milestone; unconnected UDP in Ask
  mode (sendto) is a follow-up, verdicts for it already work (block).
