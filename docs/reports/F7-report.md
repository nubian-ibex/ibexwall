<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F7 report: hardening and system plugins

Date: 2026-11-04. Plan: `docs/plans/F7-hardening-and-system.md`. ADR: 0038
(plugin ids use hyphens; ADR-0036 and 0037 were accepted at the start).

## What was done

Sixteen plugins from the spec's catalog, each with unit tests of its
check and plan logic and a scenario on real machines:

- Control and check: `system.sysctl`, `system.coredump`, `system.mounts`,
  `system.ssh`, `system.updates`, `system.firmware`, `net.nts`,
  `net.wifi`, `device.usb`.
- Check only: `system.accounts`, `system.audit`, `system.session-lock`,
  `privacy.camera-mic`, `privacy.telemetry`, `apps.flatpak-perms`,
  `vuln.cves`.

How they follow the rules of the project:

- Plugins propose, the core executes: every change is a plan of typed ops
  (owned drop-ins, `sysctl.set`, unit enable or restart, `sshd -t` before an
  sshd restart); nothing writes outside a transaction. Distro files are
  never edited; each plugin owns one file or drop-in.
- IbexWall never installs software: when the tool a plugin drives is
  missing (chrony, USBGuard, unattended-upgrades, dnf5-automatic, fwupd) the
  finding says so and the plan is refused.
- What a plugin cannot tell is "not assessed", never a pass: unreadable
  files, a DE whose settings live in a binary dconf, a package manager with
  no cache. What cannot exist on this machine is "not applicable" (rolling
  distros for updates, virtual machines for firmware, a machine with no USB
  bus for USBGuard).
- Text from other programs (account, process, network and app names, Lynis
  text, advisories) travels as Fluent arguments only; every finding uses a
  fixed key. en and pt-BR for every finding and every "may affect" note.
- Warnings: each plan carries the "may affect" notes. The one-way kernel
  lock (`kernel.kexec_load_disabled`, opt-in) carries the new
  `reboot_to_revert` flag and a "cannot be undone until the computer
  restarts" note, and its rollback removes the drop-in without failing on
  the value the kernel will not give back.

## How it was verified

- 455 workspace tests, clippy, fmt, deny and schemas clean; 84 UI tests
  (new: every plugin message parses and has both languages, every "may
  affect" key exists) and the e2e suite.
- `cargo xtask vm-test --phase f7` on fedora, ubuntu-24.04, ubuntu-26.04,
  debian and arch, 15 scenarios each:
  - sysctl: check names the live and reference values, apply sets the
    runtime values and one drop-in, rollback restores and removes it, the
    distro's files are byte-identical, the kexec lock is flagged and its
    rollback is honest.
  - coredump, mounts (drop-ins for the next boot, the live mount table
    unchanged), ssh (`sshd -T` agrees before and after, our own session
    survives the restart, rollback restores), accounts (a real
    empty-password account), audit (a real Lynis run), updates (the distro's
    tool installed, switched on and off, apt-config and systemd agree),
    firmware (a VM has nothing to update), usb (USBGuard enforcing where the
    machine has a USB bus), flatpak-perms (fabricated apps and overrides),
    cves (the plugin's count equals the package manager's own on every
    distro), camera-mic (a held video node named, and only while held),
    session-lock and telemetry (honest without a desktop, exact when a file
    decides).
  - `net.nts`: chrony installed on each distro and the servers added through
    the per-distro adapter; `chronyc -N authdata` shows chrony authenticating
    Cloudflare, Netnod, PTB and NTP.br (the four presets, now verified on real
    machines), and rollback removes both files with chrony still running.
    Ubuntu 26.04 already ships NTS sources: the check passes and nothing is
    changed.
- Regressions f1, f3, f4, f5 and f6 re-run green on fedora after the engine
  changes below.

## Defects found and fixed along the way

- The executor unit names for apply and rollback collided when a rollback
  followed an apply at once.
- Rolling back a restart re-applied the unit's prior enablement, which
  failed on units whose enablement belongs to init scripts (Ubuntu's
  ssh.service). Only what a transaction changed is put back.
- `systemctl enable` and `disable` on units that ship a SysV script
  (USBGuard on Debian and Ubuntu) rewrite `/etc/rc*.d` from the client
  side; the executor unit now has those directories writable, for apply and
  for rollback.
- systemd was not reloaded before starting, restarting or enabling a unit,
  so a drop-in written by a transaction (or restored by its rollback) was
  not seen.
- A plugin that repeated a finding id (Lynis repeats test ids) failed the
  whole check run with an internal error; the first is kept, and the plugin
  numbers its repeats.
- Fedora and Arch name no `confdir` in chrony.conf, so a drop-in would never
  be read: the adapter writes an owned configuration that `include`s the
  distro's file and an owned systemd drop-in that starts chronyd with `-f`.
- Several plugin message ids carried a dot (`plugin-system.ports-summary`),
  which Fluent drops silently; they were never used and are removed. The
  "may affect" entries of the F3 to F5 plugins were English sentences, not
  keys, so Portuguese users saw English; they are keys now, in both
  languages.

## Deviations and open points

- `system.ssh` reads sshd's configuration with sshd's own rules instead of
  running `sshd -T` (the plugin runs nothing and needs no root); the VM
  scenario proves `sshd -T` agrees before and after the change.
- `system.updates` covers automatic installation. Pending-update counts come
  from `vuln.cves`; PackageKit is not used. The dnf5-automatic drop-in
  directory (`automatic.d`) is what dnf5's documentation names; the scenario
  proves the timer and the file, not a real unattended run.
- `system.firmware` is proved only as "not applicable" on virtual machines
  and in unit tests on hardware layouts (fwupd present or absent, timer on or
  off); fwupd's HSI report and pending firmware are not read.
- `privacy.camera-mic` is a snapshot: the SDK has no monitor interface yet,
  and reading what another program holds open needs `CAP_SYS_PTRACE` and the
  real `/dev`, which the plugin's manifest declares but a plugin run as a
  child of the hardened daemon lacks (F10 gives plugins their own units; the
  scenario grants the daemon those two things to prove the logic). The
  microphone side reads a world-readable ALSA record and works anywhere.
- `system.session-lock` reads KDE's per-user files and GNOME's system dconf
  defaults; a GNOME user's binary dconf is not read, so it says "not
  assessed" until the session agent can ask the desktop.
- `privacy.telemetry` is check only: the core's browser policy op is
  DNS-only, and the other settings are distro-owned files.
- `vuln.cves` works offline from the distro's own cache. The OSV lookup for
  other ecosystems (with its privacy notice) is not built.
- `device.usb` could be proved enforcing on Fedora only: the cloud VMs of the
  other distros have no USB bus, where USBGuard cannot start, and the plugin
  says "not applicable" and refuses to plan there (also proved).
- `system.mounts` applies at the next boot by design; nothing is remounted
  live.
- `system.audit` handles Lynis only; OpenSCAP results are not parsed.
- Plugins still run as children of the daemon in this phase, so the
  capabilities and read paths in their manifests are not yet enforced by a
  unit of their own (F10).
- Spec naming applied (ADR-0038): `apps.flatpak-perms`, `system.session-lock`,
  `privacy.camera-mic`.
