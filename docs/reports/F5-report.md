<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F5 report: inbound firewall

Date: 2026-11-03. Plan: `docs/plans/F5-inbound-firewall.md`. ADRs: 0034.

## What was done

- `ibexwall-firewall`: the unified model (manager, zone, allowed ports and
  services, ports listening on every address, rules read but not edited),
  parsers for firewalld zone files and ufw rule files, the typed actions
  with the exact argv each becomes (ADR-0034: `firewall-cmd` and `ufw`
  through a fixed allowlist, never a shell), network profiles and their
  conservative recommendation.
- `net.firewall` plugin: plans `firewall.adapter` ops for a running
  firewalld or ufw; without a manager, basic inbound protection in
  `table inet ibexwall` (established, loopback, ICMP, DHCP, container and
  VPN interfaces, the chosen ports, then drop), with the services
  listening now kept reachable so the current session survives.
- Core: `firewall.adapter` execution, snapshots (the zone file, ufw's rule
  files, `firewalld.conf`), rollback that restores the bytes and reloads,
  ufw running in the executor unit with its directory and the xtables
  lock. nft fragments gained the input hook and typed conditions. The
  chains of our table are now persisted and restored at startup, which
  also fixed the F3 DNS guard surviving a reboot.
- Contract: `GetFirewall` (state plus the networks NetworkManager reports,
  read over D-Bus) and the manifest's `firewall_backends` privilege.
- Clients: `ibexctl firewall status|allow|deny|profile`, the Firewall
  screen (en and pt-BR, axe clean, controls inert with the plugin off) and
  a TUI tab.

## How it was verified

- 344 workspace tests, clippy, fmt, deny and schemas clean; 69 UI tests
  and 16 e2e (axe on both themes and locales).
- `cargo xtask vm-test --phase f5` on fedora, ubuntu-24.04, ubuntu-26.04,
  debian and arch, with a network namespace playing another computer:
  - basic protection: SSH kept, other ports dropped, allowed ports open,
    the ruleset outside our table identical before, during and after,
    chains restored after losing the table and restarting the daemon,
    full rollback leaves nothing behind;
  - firewalld and ufw: changes visible in `firewall-cmd --list-all` and
    `ufw status`, byte-exact rollback of the manager's own files, the
    default zone switched by a profile and restored;
  - Docker (real, iptables-nft) in front of all three: published port and
    container egress keep working, container reaches the host, foreign
    tables unchanged (counters ignored); firewalld alone breaks container
    forwarding until `docker0` is in the trusted zone, the documented
    arrangement, which our reload preserves;
  - a VPN-style interface stays open while another computer is dropped,
    with a foreign table untouched;
  - NetworkManager names the networks on Fedora (wired, suggested public).

## Defects found and fixed along the way

- The connect hooks of F4 blocked all connects (reported there); here,
  firewalld's `/usr/lib/firewalld` made detection claim a manager on
  machines without one: a manager is now its tool.
- systemd's `invocation:<unit>` markers are dangling symlinks, so "is
  firewalld running" read false on a running firewalld.
- A rollback through the API did not persist the restored nftables chains.
- ufw needs its directory and the xtables lock writable in the executor
  unit.

## Deviations and open points

- firewalld and ufw are driven by their CLIs with fixed argv (ADR-0034),
  not over D-Bus; reads come from their own files.
- Profiles map to firewalld's default zone; per-connection zones through
  NetworkManager, rich-rule editing and ufw application profiles are not
  in F5.
- The spike S5-a facts (what each manager writes) are recorded in the f5
  scenarios' METRIC lines; libvirt, Tailscale and NetBird were not
  installed in the VM (they need a host or an account): a veth named like
  theirs and a foreign table stand in, which is what the firewall sees.
- Coexistence with WireGuard, OpenVPN and corporate VPNs is covered by the
  same trusted-interface prefixes, not by separate installs.
