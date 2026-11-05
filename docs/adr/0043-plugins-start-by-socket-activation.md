<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0043: Plugins start by socket activation, in a unit of their own

Status: accepted (F10 M3, autonomous mode; follows the plugin contract of
spec 4.2, which already asked for one sandboxed unit per plugin).

## Context

Until F9 the core started each plugin as its own child process, so every
plugin ran inside the daemon's unit and inherited its sandbox: no `/home`, no
kernel modules, the daemon's capability set. That hid what the integrity,
persistence and antivirus plugins need, and it gave a plugin more than its
manifest declared.

## Options

1. The core starts transient units through systemd (`systemd-run`). The core
   would then be able to start a unit with properties of its own choosing,
   which is a way out of its own sandbox if it is ever compromised.
2. Static `.service` and `.socket` units generated from each `plugin.toml`
   and installed by the package; the socket unit listens on the plugin's
   socket and systemd starts the service on the first connection. The core
   only connects.
3. Keep children and widen the daemon's sandbox. Rejected: the opposite of
   the goal.

## Decision

Option 2. `cargo xtask plugin-units` (and later the packages) generate the
units; the SDK takes the listening socket from `LISTEN_FDS` and falls back to
binding it for tests and the dev sandbox. When a plugin's units are installed
and its socket does not answer, the core reports it and does not spawn the
plugin outside its sandbox. Each service runs as the manifest's user
(`DynamicUser=yes` for 26 of 27), with the capability bounding and ambient set
of the manifest, `ProtectSystem=strict`, `ProtectHome` (read-only only for
the plugins that watch home folders), `RestrictAddressFamilies=AF_UNIX`
unless the manifest asks for the network, and `ReadWritePaths` limited to the
new manifest field `sandbox.state_paths` (the state of the tools a plugin
runs).

## Consequences

- Seven manifests had to declare `CAP_DAC_READ_SEARCH` they had always used:
  ssh, nts, usb, firewall, integrity, persistence, av. `vuln.cves` is the one
  `root` plugin (dnf5 answers from its root cache only as root); it keeps one
  capability and writes only package-manager state.
- The multicall binary lives in `/usr/libexec/ibexwall/` so that SELinux
  labels it `bin_t` and the service leaves `init_t`. The SELinux module of
  F10 M5 will give the plugins a domain of their own.
- `systemd-analyze security` exposure: 1.6 to 1.8 (OK) for the sampled
  plugins. Verified on five distros (phases f1 to f9, scenario p3 asserts the
  daemon has no children and each plugin is a dynamic user under systemd).
