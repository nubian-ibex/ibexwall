<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F5: inbound firewall

Goal: let the user see and change who can reach this computer, through the
firewall the distribution already uses. Spec phase F5 and section 4.7.

Status: in progress (autonomous mode).

## Scope decisions

- **Integrate, never replace.** firewalld and ufw are driven through their
  own tools, so changes show up natively (`firewall-cmd --list-all`,
  `ufw status`). Without a manager, a `net_firewall_*` chain in
  `table inet ibexwall` offers basic inbound protection.
- **One typed operation.** `firewall.adapter` carries a structured action
  (allow or remove a port, allow or remove a service). The core validates
  it and maps it to a fixed argv; no free-form arguments reach a tool and
  no shell is involved (ADR-0034).
- **Reversible by snapshot.** The files the tool writes are captured
  before (`/etc/firewalld/zones/<zone>.xml`, `/etc/ufw/user*.rules`), and
  rollback restores them and reloads. The confirmation window with
  automatic rollback protects against locking oneself out.
- **Never touch foreign tables.** Only `table inet ibexwall` for the pure
  nftables adapter; firewalld and ufw keep their own. A test diffs
  `nft list ruleset` outside our table.
- **Read what exists.** The unified model is built from the manager's own
  files and the live listening ports; unknown rules are shown, not
  rewritten.
- **Honest limits.** Rich rules, zones beyond the default and per-interface
  assignment are read and displayed, not edited in F5.

## Milestones

M1 `ibexwall-firewall` (pure): the unified model (backend, default policy,
zone or profile, ports, services), parsers for firewalld zone XML and ufw
rules with fixtures, the typed action and its argv mapping, profile
mapping. Tests only, no system.

M2 Executor and engine: `firewall.adapter` execution with an injectable
runner, snapshots, the reload inverse, validation against the manifest,
risk flags. Fake-runner tests; byte-exact rollback tests.

M3 `net.firewall` plugin: backend detection, check (is inbound filtering
active, is anything exposed that the firewall allows), plan from a small
config (`allow`, `remove`, `profile`, `enable_basic`), the pure nftables
adapter through typed fragments.

M4 Profiles per network: NetworkManager reports the active connection;
open or unknown networks recommend the `travel` profile with a notice;
profiles map to firewalld zones when they exist.

M5 Clients: `ibexctl firewall status|allow|deny|profile`, the Firewall
screen (en and pt-BR, a11y), TUI view.

M6 `--phase f5` in the VM: firewalld (fedora, and installed elsewhere),
ufw (ubuntu, debian), pure nftables (arch, and anywhere with neither);
native visibility, no foreign table touched, byte-exact rollback;
coexistence with Docker, libvirt and a Tailscale-style foreign table.

## Spikes

- S5-a: what each manager writes for an allowed port, per distro version
  (firewall-cmd, ufw), and what a reload keeps.
- S5-b: coexistence: does `table inet ibexwall` with an input chain at
  priority filter + 5 interfere with Docker's and libvirt's rules.

## Risks

- Locking the user out (SSH): established connections stay allowed and the
  confirmation window rolls back; plans that enable default-deny include
  the services currently listening unless the user removes them.
- Reload resets runtime-only changes the administrator made; documented,
  and the snapshot is of the permanent configuration.
