<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Versions follow [Semantic Versioning](https://semver.org). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 0.2.0 (2026-11-10)

### Added

- Turn on the firewall the distribution installed when it is off (ufw on
  Ubuntu, a disabled firewalld): "Turn on the firewall" on the Firewall
  screen, or `ibexctl plan net.firewall --set enable_manager=true`. The
  services listening now stay reachable, so an SSH session survives, and
  the change can be kept or undone like any other (ADR-0046).
- The Overview lists what the protections that are on need and do not
  find, with the command that installs it on this distribution.
- A first-run welcome: how the password prompt works, a first check, the
  recommended protections to turn on with one password, what is missing,
  and the entry for a computer an organisation manages. Settings can
  open it again.
- An `ibexwall-admins` group, empty by default: its members change
  IbexWall without a password.

- The connection monitor runs after the install, and Apps and network
  has a button to turn it on or off (`ibexctl apps monitor on|off`). A
  recorded "off" is kept across upgrades and reinstalls.

### Fixed

- Allowing a port did nothing on Fedora Workstation, whose firewall zone
  already allows 1025-65535: firewalld refused to add the port, the check
  did not find it listed and the change was undone without a word. The
  plan now says the port is already allowed and by which rule.
- A plugin's own refusal reaches the app with its reason instead of a
  transport error, and `ibexctl` prints that reason after the error name.
- Block lists did nothing in a packaged install: the resolver could not
  write them. They live in `/var/lib/ibexwall-dns` now.
- The DNS screen showed the defaults after a change; it shows what is
  applied.
- Rolling back a change that started firewalld failed on the reload.
- A rollback that had turned ufw on left it on.
- Removing the packages left the monitor's link behind, and a monitor
  still running could start the daemon again during the removal.

## 0.1.1 (2026-11-09)

Makes the desktop app usable by a person who is not root. Found by
installing 0.1.0 from the release on Fedora 45 and Ubuntu 26.10 with KDE.

### Fixed

- Changes from the desktop app or `ibexctl` (turning a plugin on, the
  firewall, DNS, undoing a change) were refused for every user but root,
  with no password prompt. They now ask for the password through the
  desktop's authentication dialog (ADR-0045). `ibexctl` asks on a
  terminal; `--no-ask-password` turns that off. The MCP server never asks.
- Buttons that failed said nothing; the app now shows why a change did
  not happen, and that it waits while the password dialog is open.
- The monitor never received the secure resolver's answers in a packaged
  install (a permission on its socket's directory). The socket moved to
  `/run/ibexwall/answers.sock` and only the resolver may write to it;
  before, any local user could.
- `ibexctl audit verify` called the audit chain broken on a fresh install.
- The sidebar scrolled away with the page, and its "Protection active"
  line never changed. Only the content scrolls now, and the line reports
  the service.
- The Organisation screen showed message ids instead of text, was in the
  menu of every machine and could not load for a person. It now appears
  only when an organisation manages the machine, with an explanation in
  Settings.

### Added

- `allowInteractiveAuthentication` on the methods that change the
  machine, and the `AuthenticationRequired` error (additive API change).
- `managed` in `com.ibexwall.Policy.GetEffective`, which now needs only
  the read permission.
- A test phase that runs IbexWall as a person instead of root, on the
  five distributions.

## 0.1.0 (2026-11-08)

The first release, with deb, rpm and Arch packages.

The delivered work, each tested on Fedora, Ubuntu, Debian and Arch:

- the daemon, CLI, terminal UI and desktop app;
- firewall and per-program network control (eBPF), secure DNS, system posture,
  updates, accounts and hardening;
- endpoint plugins for VPN, isolation, persistence, integrity and antivirus;
- an MCP server for AI assistants that can read and suggest, never apply;
- 32 official plugins, one signed multicall binary, each in its own sandbox;
- an SELinux module and AppArmor profiles;
- RPM, DEB and Arch packages with clean install, upgrade, removal and purge;
- signed artifacts, an SBOM, a provenance statement and reproducible builds;
- the website (ibexwall.com), the documentation (docs.ibexwall.com) and the
  plugin index, in English, Portuguese, Spanish, French and German.

See `docs/release-checklist.md` for what version 1.0 still requires.
