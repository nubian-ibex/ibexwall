<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F9 report: VPN and endpoint

Date: 2026-11-04. Plan: `docs/archive/plans/F9-vpn-and-endpoint.md`. ADR: 0040
(OpenVPN import deferred; proposed, the maintainer decides).

## What was done

Five plugins and the engine groundwork they needed.

- `endpoint.isolate` (emergency mode): two owned chains ahead of every other
  table accept loopback and an allow list (replies of established
  connections always, new ones limited to the named ports) and drop the
  rest. A network change, so it needs a confirmation and reverts if nobody
  gives one; turning it off is the transaction's rollback. An empty allow
  list is refused unless `lockdown=true`.
- `net.vpn`: a `wg-quick` profile becomes an owned 0600 NetworkManager
  keyfile (hooks such as `PostUp` are refused) plus a secret-free record the
  check and the kill switch read; NetworkManager is told to re-read its
  directory. The kill switch is one output chain: loopback, the tunnel
  interfaces, the VPN servers (as addresses; a name would itself be a leak),
  DHCP, link-local and an allow list pass, the rest drops. The check names a
  VPN without a kill switch, the conflict with `net.dns` when the profile
  brings its own DNS, and explains a blocked machine when the tunnel is
  down.
- `endpoint.persistence`: units and timers, cron, autostart, shell start-up
  files and `LD_PRELOAD` are hashed; findings are what is new or changed
  since a baseline the person accepted (a plan, so audited and reversible).
  A preloaded library is a high finding with or without a baseline.
- `endpoint.integrity`: `rpm -Va`, `dpkg --verify` or `pacman -Qkk` (and AIDE
  when set up). Configuration, docs, mode-only or time-only differences and
  paths the daemon's own sandbox masks are left out; a changed program file
  is high.
- `endpoint.av`: a oneshot unit and an optional timer the plugin owns run
  ClamAV and YARA over explicit folders; the check turns what the scanners
  printed into findings. Nothing is installed; a missing scanner or database
  is said, and so is SELinux standing in the way.

Engine and tooling changes:

- The typed nftables rule gained `oif_prefix`, `saddr` and `daddr`
  (validated, IPv4 and IPv6 in separate rules).
- A file written with a private mode shows its line count, not its content,
  in previews, proposals and dry runs.
- A manifest can mark an allowlisted `exec` as `symmetric`: the rollback runs
  it again after the files are restored. NetworkManager needs this; a
  restart instead leaves a live, adopted tunnel behind.
- `ibexctl plan --set-file KEY=PATH` for profile text.
- `net.vpn` joins the plugins closed to every MCP client by default.

## How it was verified

- 536 workspace tests, clippy, fmt, deny and schemas clean.
- `cargo xtask vm-test --phase f9` on fedora, ubuntu-24.04, ubuntu-26.04,
  debian and arch, five scenarios each:
  - isolation: the session and loopback survive, the internet, other hosts
    and DNS are cut, rollback leaves foreign tables identical, an
    unconfirmed isolation reverts on its own;
  - persistence: the five persistence cases and a preloaded library, the
    baseline going quiet, one new and one changed entry named by path, the
    baseline rolled back;
  - integrity: an extra byte on a real installed binary is found, the
    configuration stays out, restoring it quiets the check;
  - antimalware: the EICAR file is flagged by ClamAV and by YARA, the clean
    file next to it is not, a rescan after removal is clean, a weekly timer is
    enabled and rolled back, every file the plugin wrote is gone;
  - VPN (the acceptance check): with the tunnel dropped and no kill switch
    24 to 30 packets leaked to the uplink in `tcpdump`; with the kill switch
    the same probes put 0 on it, the tunnel reconnected under the kill
    switch, and both rollbacks left no chain, marker, keyfile, record or
    interface. The private key appears in no preview.
- Regressions f1, f3, f4, f5, f6, f7 and f8 re-run green on fedora after the
  engine changes; the UI suite (91 tests, e2e with axe) is unchanged and green.

## Defects found and fixed along the way

- The first NetworkManager import restarted the service; the new process
  adopted the orphan WireGuard device and the rollback left a working tunnel.
  Import now only tells NetworkManager to re-read, and the engine got the
  symmetric exec to run it again on rollback.
- The package verifier deadlocked on a full pipe (its output is large);
  output is now read while it runs.
- The Arch verifier reports on stderr, so it saw nothing.
- The integrity check reported thousands of paths because the daemon's
  hardened unit hides `/home`, `/root` and `/usr/lib/modules`; the check now
  keeps to strong signals outside those.
- A scan unit with `StandardOutput=truncate:` let the second scanner erase
  the first one's findings.
- Under enforcing SELinux a confined `clamscan` read nothing and wrote
  nowhere systemd could; the check now names the boolean
  (`antivirus_can_scan_system`), and each scanner writes its log where its
  policy allows.
- Debian images have no `nft`; Ubuntu Server leaves a WireGuard device
  unmanaged under NetworkManager; Ubuntu 26.04 confines `wg` with AppArmor.
  The scenarios provision or work around each, and say so.

## Deviations and open points

- OpenVPN import was added after acceptance (ADR-0040 accepted, subset in
  `docs/openvpn-subset.md`, VM scenario v2 on five distros).
- Scan folders are explicit. The daemon's unit hides `/home`, so a plugin
  cannot discover Downloads folders; own units per plugin (F10) fix this.
- No file watcher for persistence: the SDK has no monitor interface yet.
- Integrity is limited by the same sandbox (see above) until plugins run in
  their own units.
- The kill switch accepts link-local traffic and the multicast groups
  neighbour discovery needs; those do not leave the link but are not
  "inside the tunnel". Servers behind a name cannot be allowed (resolving
  would leak); the person gives the address.
- Ubuntu Server: NetworkManager kept the WireGuard device unmanaged, so the
  VM test brought the tunnel up by hand there. The plugin's own import
  against NetworkManager is verified on Fedora, Debian and Arch.
- ClamAV signatures are not downloaded by IbexWall; the test uses the real
  scanner with the distro's database plus one EICAR signature.
- There is no VPN or antivirus screen: the generic plugin cards, findings
  and the History carry them.

## Decisions for the maintainer

- ADR-0040: defer OpenVPN import, or build the documented subset (option 2).
