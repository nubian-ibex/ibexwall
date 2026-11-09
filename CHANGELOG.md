<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Versions follow [Semantic Versioning](https://semver.org). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 0.1.1 (unreleased)

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
