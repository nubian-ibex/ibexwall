<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F7: hardening and system plugins

Goal: the hardening catalog ships as plugins that check, and where the spec
says so, change the system through plans with snapshot and rollback, with
the "may affect" and reboot-to-revert warnings the spec demands. Spec phase
F7; decisions ADR-0036 to 0038 are in force (plugin ids use hyphens).

Status: in progress (autonomous mode).

## Approach

Every plugin follows the shapes that already exist: checks read files under
a sandbox and never run commands (like `system.posture`, `system.ports`);
controls plan typed `Op`s the core executes (like `net.firewall`); adapters
that must drive another program use the fixed-argv `Exec` op or a dedicated
adapter op (ADR-0034 pattern). Each milestone lands with its own VM
scenarios under `--phase f7` and the battery (fmt, clippy, nextest, deny,
schemas, UI checks) before the commit.

## Milestones

M1 `system.sysctl`: the reference table from the spec as data (value, why,
may-affect notes); check compares live values; control plans `sysctl.set`
ops plus one owned drop-in under `/etc/sysctl.d/` so it survives reboot;
`rp_filter` and `kernel.sysrq` are opt-in only (VPN, multi-homing, desktop
debugging); `kernel.kexec_load_disabled` is opt-in and carries the
reboot-to-revert warning (one-way until reboot).

M2 Local daemons and files: `system.ssh` (`sshd -T` parsed for the check;
control writes an owned drop-in under `/etc/ssh/sshd_config.d/` and
reloads), `system.coredump` (systemd-coredump config: storage=none,
ProcessSizeMax=0), `system.mounts` (`/tmp` and `/dev/shm` hardening via
owned units, not fstab edits), `system.accounts` (check-only: PAM,
faillock, empty passwords, sudoers NOPASSWD).

M3 Update and firmware: `system.updates` (PackageKit pending updates,
automatic updates status; control enables dnf-automatic /
unattended-upgrades), `system.firmware` (fwupd: pending firmware, HSI
report via `fwupdmgr`), `system.audit` (check-only; runs Lynis or
OpenSCAP/SSG when installed and parses their reports; never installs or
bundles them).

M4 Network-facing: `net.nts` (chrony with NTS: check `chronyc -N authdata`
for authenticated peers, control writes an owned `/etc/chrony.d/` drop-in
with the spec's servers and distro adapters for chrony's paths), `net.wifi`
(NetworkManager MAC randomization, open-network warning; check reads NM
files, control uses `nm.setting`).

M5 Devices and privacy: `device.usb` (USBGuard: control installs nothing,
plans its rules file when USBGuard is present, check reports state),
`privacy.camera-mic` (monitor: PipeWire camera/microphone use events),
`privacy.telemetry` (check and control of distro and app telemetry:
Ubuntu pro/popularity-contingent counters, Mozilla/Chrome policies),
`system.session-lock` (check via the session agent: is a screen lock
configured and idle-locked), `apps.flatpak-perms` (check-only: dangerous
permissions per app), `vuln.cves` (distro sources first: dnf
updateinfo, Ubuntu USN/OVAL, Arch security tracker data; OSV for other
ecosystems with an explicit privacy notice and an offline mode).

M6 Finish: UI locale entries for every finding and plan template (en and
pt-BR), the Plugins screen picking the new plugins up, TUI untouched unless
a plugin needs a tab, the F7 report, STATUS, and the full five-distro run.

## Out of scope (kept for later phases)

- F8's assistant queue, F9's endpoint plugins, packaging per distro.
- Any change applied without a plan: nothing in F7 writes outside a
  transaction the user confirmed.
- Bundling Lynis, OpenSCAP, USBGuard or ClamAV: integration when present,
  proposal to install otherwise.

## Risks

- Sysctl values interact with distro defaults (Debian sets
  `kernel.kptr_restrict=1`): the check reports the live value, the plan
  only offers the spec's table, and rollback restores the prior value.
- `kernel.kexec_load_disabled` cannot be undone without a reboot: it is
  opt-in, the plan says so, and rollback reports honestly if the kernel
  refuses the restore.
- `sshd -T` needs root on some distros: the check reports "not assessed"
  when it cannot read, never a pass.
- CVE sources differ per distro: `vuln.cves` starts with what the distro
  ships locally (updateinfo, OVAL) and only then offers OSV, off by
  default.
