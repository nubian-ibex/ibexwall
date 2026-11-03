<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0036: Ask is driven by the core, and its nft chains are derived state

Status: accepted for F6 (autonomous mode); needs the user's confirmation
because it departs from "plugins propose, the core executes through plan,
snapshot, approval and rollback" for one narrow case. Phase: F6.

## Context

An app in Ask mode needs, besides the eBPF hook (ADR-0035): nftables rules
that queue the first packet of its flows, a queue listener, a place where
the question waits for the user, and a way to remember answers. The mode
itself is a setting the user changes (`ibexctl apps set`, polkit
`com.ibexwall.apps.decide`, audited), not a system change a plugin
proposes.

## Decision

1. The monitor unit (the only holder of the eBPF and queue capabilities)
   sends `{"ask": {...connection fields..., "ask_id": N}}` to the core over
   the monitor socket and holds the packet. The core answers with
   `{"answer": {"id": N, "decision": "allow"|"block"}}` on the same socket.
   Policy (`{"policy": ...}`) travels the same way, on connect and on every
   change.
2. The core keeps the open questions in memory (`ListPrompts`), coalesces a
   retransmission or a parallel connection of the same question, and
   publishes an `apps.ask` event. `AnswerPrompt` takes a decision and a
   scope: once, this destination (stored per app, destination and port;
   answered without asking from then on), or always (the app's mode changes
   and the policy is pushed). The stored mode is the truth: a question that
   arrives after the mode changed is answered without asking.
3. Nobody answering is not an error. The unit applies the fallback (default
   `allow`, settable to `block`) when the timeout (default 30 s) passes. If
   the core goes away the unit exits, which detaches the programs and
   closes the queue: held packets are dropped once and the retransmission
   is accepted (measured: the connection completes after about 1 s on all
   five distros).
4. The two nft chains (`apps_ask` queue at priority 5 and `apps_ask_refuse`
   at priority 6, own table only) are reconciled by the core: installed
   when any app or the default is in Ask mode, removed when none is,
   persisted with the other chains. This is derived state, applied
   idempotently, so it does not go through plan, approval and a
   transaction. The rollback is the mode change the user already made, and
   the queue rule carries `bypass`, so a missing listener means the packet
   is accepted.

## Consequences

- The unit's `RestrictAddressFamilies` gains `AF_NETLINK` (the queue is a
  netlink socket). With `CAP_NET_ADMIN` that is more than the unit needed
  before; the alternative (a helper process for the queue) was not worth a
  second privileged binary. Recorded in the unit file.
- The decision to skip the transaction machinery for these chains is the
  deviation. If the user prefers the strict path, the chains move into a
  built-in plugin that proposes them whenever the mode set changes, at the
  cost of an approval prompt each time the first app is put in Ask mode.
- A cgroup created after the policy (a Flatpak app launched after the rule)
  is covered by the loader's rescan every two seconds, so its first
  connections in that window are not held or blocked. An event-driven
  rescan (a raw tracepoint on cgroup creation) is the follow-up.
- Unconnected UDP (`sendto`) in Ask mode is not held yet; `block` covers it.
