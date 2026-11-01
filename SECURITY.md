<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Security Policy

IbexWall runs privileged on Linux desktops and changes network, DNS and
kernel behavior. We treat security reports with priority.

## Reporting a vulnerability

Please report privately via [GitHub Security Advisories][ghsa]
("Report a vulnerability" on the Security tab of this repository).
Include reproduction steps, affected components and, if possible, a
proof of concept.

A `security.txt` and a dedicated contact key will be published with the
project website; until then GitHub private vulnerability reporting is the
supported channel.

[ghsa]: https://github.com/nubian-ibex/ibexwall/security/advisories/new

## Scope highlights

- The daemon (`ibexwalld`), its varlink API surface and polkit actions.
- The plugin supervisor, manifest validation and sandbox generation.
- The change engine (snapshot, rollback, crash recovery), since a failure
  here can leave systems inconsistent.
- The DNS resolver and its integration drop-ins.
- The web gateway and the MCP server (untrusted-input handling).
- CI/release pipeline and dependency chain (report supply-chain findings
  here too).

## Honest limits

Malware with root privileges can disable IbexWall; we are defense in
depth, not a hypervisor. Documented limits live in
`docs/threat-model.md`; if you find an unlisted bypass, we want to hear
about it.

## Supported versions

Pre-alpha: only the `main` branch. First supported releases will be listed
here.
