<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0034: firewalld and ufw are driven by fixed argv

Status: accepted for F5 in autonomous mode; the maintainer may reverse it.
Phase: F5.

## Context

Spec 4.7 says firewalld is driven over D-Bus and ufw through its CLI with
fixed argv. The change engine executes typed operations and snapshots the
files they change.

## Options

1. firewalld over D-Bus (zbus), as the spec says. Structured, but each
   method has a signature to get right, runtime and permanent are separate
   interfaces, and the executor runs in a transient hardened unit that must
   then reach the system bus.
2. `firewall-cmd` with fixed argv, like ufw. firewall-cmd is a client of the
   same D-Bus API, so the effect is identical and natively visible; the
   argv is built by the core from a validated action, never from plugin
   text.

## Decision

Option 2 for the F5 write path. Reading uses the manager's own files
(firewalld zone XML, ufw rules) plus the live listening ports, so the
plugin sandbox needs no tool access. Moving the reads or writes to D-Bus
later does not change the operation's contract.

## Consequences

- The binaries are an allowlist in the core (`/usr/bin/firewall-cmd`,
  `/usr/sbin/ufw`); an action maps to exactly one argv.
- Rollback restores the snapshotted files and runs the fixed reload
  (`firewall-cmd --reload`, `ufw reload`).
