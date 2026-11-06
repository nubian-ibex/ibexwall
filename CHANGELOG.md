<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Versions follow [Semantic Versioning](https://semver.org). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

The first release, v1.0, is in preparation. The delivered work so far, each
tested on Fedora, Ubuntu, Debian and Arch:

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
