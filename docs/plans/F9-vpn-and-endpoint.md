<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F9: VPN and endpoint

Goal: five plugins from the spec's catalog, each with unit tests and a
scenario on real machines, and the four acceptance checks of the phase:
a dropped tunnel leaks nothing (`tcpdump`), the EICAR test file is detected,
persistence cases are detected, and isolation reverts completely.

Status: delivered 2026-11-04 (report: `docs/reports/F9-report.md`).

## Milestones

M1 Engine groundwork. Two gaps stop the network plugins: the typed nftables
rule cannot match an interface name prefix on output or an address, and a
plan preview prints the content of every file it writes (a VPN key would
appear in the UI, in `ibexctl plan` and in `dry_run`). `Rule` gains
`oif_prefix`, `saddr` and `daddr` (validated CIDRs, IPv4 and IPv6 split into
their own rules); a file written with a private mode (no group or other
bits) shows "private file, N lines hidden" instead of its content.

M2 `endpoint.isolate` (control): emergency mode. One owned input chain and
one output chain drop everything except loopback and an allow list (address,
optional protocol and ports). Network risk, so the engine asks for a
confirmation and reverts if nobody confirms; rollback removes the chains and
nothing else. The allow list always has to name something the person needs
(the plan refuses an empty one unless `lockdown=true`, because an empty list
cuts the machine off entirely).

M3 `net.vpn` (check, control): WireGuard profiles through NetworkManager
(parse a `wg-quick` file, write an owned keyfile with mode 0600, reload),
OpenVPN profiles through `nmcli connection import` when NetworkManager's
OpenVPN plugin is installed (IbexWall installs nothing), and the kill
switch: an output chain that accepts loopback, the tunnel interfaces, the
VPN endpoints (so the tunnel can come back), DHCP and an explicit allow
list, and drops the rest. Coherence with `net.dns`: findings when the
secure resolver is on and the VPN profile brings its own DNS, and the kill
switch never opens a path the resolver's guard closed.

M4 `endpoint.persistence` (check): a baseline of the places a program
persists (system and user units and timers, cron, XDG autostart,
`/etc/ld.so.preload`, shell start-up files, `/etc/profile.d`) stored under
the plugin's own state directory; findings for what is new or changed since
the baseline, and always for `ld.so.preload` entries. Accepting the current
state as the baseline is a plan (a file write), so it is audited and can be
rolled back. No watcher: the SDK has no monitor interface yet (open since
F7); the check runs on the scheduler.

M5 `endpoint.integrity` (check): the package manager's own verification
(`rpm -Va`, `dpkg --verify`, `pacman -Qkk`), configuration files left out
(they are meant to change), plus AIDE when installed and initialised.
Findings name the package and the file; a changed binary is high severity.

M6 `endpoint.av` (check, control): ClamAV on demand and scheduled, YARA on
Downloads. IbexWall installs neither; the check says what is missing. The
scan is a oneshot unit and a timer the plugin owns; results are read from a
log the unit writes, so findings come from what the scanner reported, not
from the plugin re-judging files. Acceptance uses the EICAR string.

M7 Report, STATUS, threat model section, five-distro run, regressions.

## Out of scope

A VPN or antivirus screen (the generic plugin cards and findings carry
them), real-time on-access scanning, a file watcher, installing any tool,
and provider-specific VPN integrations.

## Risks and how they are handled

- Cutting the machine off: both network plugins are network-risk changes,
  the engine reverts them unless confirmed, and the VM test names the
  administrator's SSH peer in the allow list.
- Secrets: a private key appears in no preview, no audit row (digests only)
  and no log; the keyfile is 0600 root.
- A scanner or verifier that takes minutes: they run as oneshot units or
  with a time limit, never inside the check call without one.
- Noise: integrity ignores configuration files and docs; persistence
  reports differences from a baseline the person accepted.
- Honest limits stay in the report: ClamAV signature updates, OpenVPN
  coverage, no real-time watching.
