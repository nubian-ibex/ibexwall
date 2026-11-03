<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0033: the Flatpak network block writes the override file

Status: accepted (spike S4-c done, 2026-11-03). Phase: F4.

## Context

F4 must block a Flatpak app and revert it. `flatpak override` exists, but
the core executes typed operations only (no shell, no free-form exec), and
rollback must restore the exact bytes.

## Decision

`flatpak.override` is a typed operation the core executes by writing the
file Flatpak itself reads: `/var/lib/flatpak/overrides/<app-id>` (the
default system-wide installation). It accepts exactly one change,
`--unshare=network`, for a syntactically valid application id (three or
more dot-separated elements of `[A-Za-z0-9_-]`). The engine snapshots the
file like any other, so rollback restores the administrator's bytes or
removes the file we created. The plugin refuses apps that are not
installed system-wide, so a typo cannot leave a stray file.

## Findings (Flatpak 1.14.6, 1.16.6, 1.18.4 on the five distros)

- `flatpak override --system --unshare=network <app>` writes
  `[Context]\nshared=!network;\n` (27 bytes, 0644 root) in that directory.
- Merging into an existing file edits the `shared=` list. The order of the
  entries differs between versions (`ipc;!network;` on 1.18.4,
  `!network;ipc;` on 1.14.6 and 1.16.6); Flatpak reads both. Ours keeps the
  administrator's entries and appends, so the result is valid everywhere.
- `flatpak override --system --show <app>` prints the merged view; the VM
  scenario uses it to prove Flatpak parses our file the same way.
- Documentation: <https://docs.flatpak.org/en/latest/flatpak-command-reference.html>
  (`flatpak-override`, consulted 2026-11-03).

## Consequences

- Per-user installs (`~/.local/share/flatpak`) are out of reach: the core
  does not read home directories. The Apps screen must say so.
- Unblocking is the transaction's rollback; there is no separate "allow"
  operation yet.
- The op carries no network risk flag: cutting one app cannot lock the
  machine out, so it needs no confirmation window.
- The F4 plugin is `apps.flatpak-network`. The specification reserves
  `apps.flatpak_perms` for the F7 audit plugin, and that id breaks the
  manifest rule `[a-z0-9-]` (the same spec lists `system.session_lock` and
  `privacy.camera_mic`). The spec and the rule need reconciling; reported
  to the maintainer, not decided here.
