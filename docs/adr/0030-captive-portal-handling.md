<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0030: Captive portals are detected and announced, never auto-relieved

Status: accepted (F3, 2026-11-02). Spec section 4.8 asks for temporarily
allowing the DHCP DNS for the portal login "with a warning".

## Context

Enforcement refuses clear DNS from everyone but the resolver, and the
resolver's encrypted upstream is usually blocked by a captive portal. The
login page then may not load, which looks like IbexWall broke the network.

## Options

1. The session agent asks the core to lift enforcement for a short time
   when NetworkManager reports a portal. Needs a new authorized core
   method; an unprivileged session process would be able to switch off a
   protection.
2. A NetworkManager dispatcher script (root) lifts enforcement on every
   portal state change. A malicious access point that fakes the portal
   probe could then disable enforcement silently and persistently.
3. Detect the portal, notify the user with the exact relief steps, and let
   them apply the change through the reviewed flow (chosen).

## Decision

Option 3 for v0.1: the agent polls NetworkManager's connectivity state and
raises one notification per portal episode (en and pt-BR by session
language) telling the user to turn "Refuse unencrypted DNS" off, sign in,
and turn it back on. Enforcement is never lifted as a side effect of
network conditions. Option 1 stays open for a later release with a
dedicated polkit action and a hard time box, if friction reports justify
it.

## Consequences

- A faked portal cannot weaken the machine; the worst case is one
  notification.
- The notification names the relief steps, so the user does not have to
  discover them.
- Portal episodes cannot be exercised in the QEMU user-mode network, so
  this is covered by unit tests plus the language test, not a VM scenario.
