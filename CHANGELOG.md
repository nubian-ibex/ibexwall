<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changelog

Versions follow [Semantic Versioning](https://semver.org). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 0.6.0 (2026-11-26)

### Added

- System snapshots (ADR-0050), off by default: where snapper has a `root`
  configuration, IbexWall takes a snapshot before a change marked with risk
  and another after it. If the first one fails, nothing is changed and the
  reason is shown. Turn it on in Settings or with `ibexctl snapshots on`;
  History shows the snapshot numbers. IbexWall never configures snapper,
  deletes a snapshot or restores one.
- Desktop app: where Secure DNS cannot manage the machine's DNS setup (for
  example NetworkManager without systemd-resolved), the screen says so before
  anything is chosen, points to the guide and offers to check again.

### Fixed

- Packages: removing IbexWall on Debian and Ubuntu no longer logs an
  AppArmor refusal.
- Desktop app: the window no longer stays white in VMware and VirtualBox
  guests with an X11 session.

## 0.5.1 (2026-11-26)

### Added

- Desktop app: a "Settings file" section in Settings saves IbexWall's own
  settings to a file in your home folder, and imports one after showing what
  it would change.

### Fixed

- Desktop app: the History screen failed to load, and restore points could
  not be used from it, since 0.4.0: the window was never allowed to call the
  restore point commands.
- Importing a state file: the dry run now lists every setting that differs,
  including profile settings and settings the file would remove, and
  `ibexctl import` counts them correctly and names the locked ones. A setting
  the organization locks keeps the value this machine has.
- Packages: no more AppArmor refusal while installing on Debian and Ubuntu
  (the daemon briefly started unconfined), and no SELinux refusal while
  removing on Fedora.

## 0.5.0 (2026-11-26)

### Added

- The portable state file (ADR-0049, approved): `ibexctl export [FILE]`
  writes one readable JSON with the settings layers, which plugins are
  enabled, the restore point names and a digest that catches edits.
  `ibexctl import FILE` shows a dry run first (what differs, what the
  organization keeps locked), writes the layers and plugin states, and
  never changes the machine: the person then reviews and applies as
  usual. The organization layer and its locks are refused in the file.

### Fixed

- Ask mode with thousands of connections waiting at once could let some of
  them out unasked, even with the fallback set to block: the table that
  remembers who is being asked was smaller than the range of connection ids,
  and dropped the oldest entry. It now covers the whole range.

## 0.4.1 (2026-11-20)

### Fixed

- After a change was applied, kept or undone, the screen could still show it
  as pending: the stored findings of the affected plugin were refreshed only
  by the next explicit check. Apply, Confirm, Rollback, the automatic
  timeout and a restore now re-check the plugin, so Hardening (and every
  other screen) reflects the machine right away.

## 0.4.0 (2026-11-20)

### Added

- Restore points (ADR-0048): name the state now, and later undo every change
  IbexWall committed after it, newest first. `ibexctl restore-point
  create|list|go`, and a card on History in the app. A failure part-way stops
  and names the transaction; a retry repeats only what is still in place. The
  undo set follows insertion order, because several changes can land in the
  same second.

### Changed

- argon2 0.6 and jsdom 31, major bumps the maintainer accepted.

## 0.3.0 (2026-11-20)

### Changed

- The app queues changes in one place. A bar at the bottom of the window
  shows how many are ready ("3 changes ready") with Discard and "Review and
  apply"; the review opens in a panel with three numbered steps, Review,
  Apply and Keep, replacing the Simulate, Apply and Confirm buttons that each
  screen had. Hardening and Secure DNS add what you choose to the bar; the
  Firewall, Apps, Plugins and Assistant open the panel from their own action.
- Secure DNS is split into tabs (Provider, Block lists, Protection, Own
  servers), with a dot on a tab that holds a change.
- The sidebar shows the version, every screen uses the same width, and the
  window opens at 700 px so it fits an 800 px screen.

## 0.2.1 (2026-11-18)

### Fixed

- `system.mounts` judges `/dev/shm` and `/tmp` from the host mount table,
  not from its own namespace (a VM check showed it was wrong).
- With the Ask fallback set to block, a burst of new flows that filled the
  Ask queue no longer leaves unasked: a full queue follows the fallback
  (ADR-0047, proposed). The queue holds 4096 packets instead of 1024.
- The daemon starts when one configuration file is unreadable, such as a
  truncated `org.toml`: the file is ignored, reported as degraded in
  `ibexctl status`, and left for you to fix.

### Changed

- `system.ssh` has a `confirm_keys` setting: where AppArmor hides `~/.ssh`
  from the plugin (Ubuntu, Debian), check by hand, then plan with
  `confirm_keys=true`.
- UI toolchain updates (vite, typescript-eslint, playwright, lucide).

## 0.2.0 (2026-11-13)

### Added

- Turn a running ufw or firewalld off from the Firewall switch; undoing it
  turns it back on.

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
- Apps and network shows each program's icon and name from its desktop
  entry (flatpak, snap, desktop and plain programs), with the path of its
  binary under the name.
- A catalog of assistants to connect, as cards: Claude Code, OpenCode,
  VS Code, and now Cursor and Gemini CLI (`ibexctl mcp config cursor`,
  `gemini-cli`). The network form is not offered for Gemini CLI.

- The connection monitor runs after the install, and Apps and network
  has a button to turn it on or off (`ibexctl apps monitor on|off`). A
  recorded "off" is kept across upgrades and reinstalls.

### Fixed

- The Firewall switch shows what the firewall is doing now, not whether the
  plugin is on. Port, service and profile controls appear only while the
  firewall is on, and asking for a change turns the plugin on by itself.
- The screen reads the firewall again after a change is applied, kept or
  undone, so an allowed port shows up in the list.
- The change flow says what each button does: "Apply" only shows what would
  change, "Confirm" carries it out.

- Allowing a port did nothing on Fedora Workstation, whose firewall zone
  already allows 1025-65535: firewalld refused to add the port, the check
  did not find it listed and the change was undone without a word. The
  plan now says the port is already allowed and by which rule.
- A plugin's own refusal reaches the app with its reason instead of a
  transport error, and `ibexctl` prints that reason after the error name.
- Block lists did nothing in a packaged install: the resolver could not
  write them. They live in `/var/lib/ibexwall-dns` now.
- The DNS screen showed the defaults after a change; it shows what is
  applied (the choice is kept beside the resolver's settings).
- Changing the DNS provider or block list after the first time was written
  and ignored: the running resolver was never restarted. It is restarted
  once per change, and a few changes close together no longer trip its
  start limit.
- The Firewall screen says, in your language, when a port is already
  allowed by a range or when the firewall must be turned on first.
- Rollbacks no longer run on the daemon's async threads, which could stall
  its watchdog.
- Removing the packages with several DNS changes applied left two of them
  undone: the rollbacks tripped the resolver's start limit, and the removal
  tried to start the resolver it was removing. A rollback now clears the
  start limit, and a removal leaves IbexWall's own services stopped.
- The daemon's watchdog is three minutes instead of 30 seconds: a machine
  short of CPU, or a paused VM, had the healthy daemon killed.
- Rolling back a change that started firewalld failed on the reload.
- A rollback that had turned ufw on left it on.
- Removing the packages left the monitor's link behind, and a monitor
  still running could start the daemon again during the removal.
- Ctrl-C on `ibexctl apply` or `rollback` no longer leaves the transaction
  stuck in `applying`: a call keeps running after its client hangs up, and
  only the wait for the password dialog is cancelled.
- Apply and policy changes are refused when the audit log cannot record
  them, and a late Confirm (after the deadline) is refused.
- After a crash, a rollback that failed is no longer replayed over a newer
  change, and recovery undoes in newest-first order. The snapshot sweep no
  longer deletes snapshots when its query fails.
- A proposal whose apply fails goes back to pending; the proposal quota
  counts per user, and the API closes idle connections, caps connections per
  user and rejects oversized requests.
- The resolver answers socket stays closed when its group is missing.
- Turning a firewall on keeps every exposed TCP listener and the sshd port,
  and fails on invalid extra input. Removing the live SSH port or service, or
  switching to the travel profile, is refused unless `confirm_ssh_cut=true`.
  Blocking `network-filesystems`, `rare-filesystems` or `bluetooth` is refused
  while something uses them, unless `confirm_in_use=true`.
- A rollback keeps a symlinked file a symlink, and a unit it created is
  disabled again. The privileged helper never gets `/` or `/run` as writable.
- No more false High finding for `/etc/shadow` permissions on Debian, Ubuntu
  and Fedora; fewer false positives in the integrity check; the antivirus scan
  unit starts on machines with YARA only.
- SSH: turning passwords off is refused without a usable key and also turns
  off keyboard-interactive login; the checks ignore case, follow include
  globs, and `verify` confirms the setting took effect.
- The VPN kill switch also blocks forwarded traffic from containers and
  hotspots, and its DHCP rule is narrower. A hostname endpoint names the
  profile in the error.
- The `/tmp` and `/dev/shm` mount verdicts come from the host mount table,
  and show not assessed when it cannot be read.
- Posture flags only a passwordless `ALL` sudo grant and follows includes; an
  Info note lists plain time sources next to NTS ones.
- The connection monitor loader keeps the rules in force and reconnects when
  the core restarts, and exits loudly on a fatal Ask queue error. Package
  queries have a timeout and run off the Ask thread. The kernel's exec path
  wins over `/proc/<pid>/exe`.
- MCP: `explain_finding` hides findings of denied plugins; concurrent MCP
  clients keep one audit chain.
- DNS: CNAME-cloaked trackers are blocked, downloaded-list allow entries can
  no longer unblock the DoH canary, and a corrupt `resolver.json` keeps
  enforcement on after a failure. Binary-change alerts are no longer masked
  by unrelated package updates. The agent exits when the core drops.
- The admins polkit rule applies only to local, active sessions. Upgrading
  from 0.1.1 no longer turns the monitor on if it was off. A purge keeps
  snapshots and `state.db` when the removal cleanup failed.
- Release checksums and signatures now cover the deb, rpm and Arch packages.
- The keep countdown follows the real deadline and shows "undone" at zero;
  Keep and Undo no longer fire twice on a double click; a partial hardening
  undo can be retried; the prompt window stays open when the core is
  unreachable and has its own narrow Tauri capability.

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
