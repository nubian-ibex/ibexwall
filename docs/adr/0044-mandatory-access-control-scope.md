<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0044: What the SELinux and AppArmor policies confine

Status: accepted (F10 M5, autonomous mode; the spec asks for an SELinux module
and AppArmor profiles, without saying which programs).

## Context

IbexWall runs five kinds of program: the daemon (root; edits `/etc`, drives
systemd and nftables), the secure DNS resolver (parses untrusted network
data), the MCP server (listens on the network when the person turns it on),
the plugins (one signed multicall binary, one unit each) and short helpers
(`ibexwall-exec`, the eBPF loader, the session agent).

## Options

1. Confine everything, the daemon included. The daemon's job is to write
   whatever the plugin manifests declare, across `/etc` and the units, so its
   policy would be close to the set of all files that matter, and a mistake in
   it breaks the repair of the machine it protects.
2. Confine only the programs that parse untrusted input or run without a need
   to write: the resolver, the MCP server and the plugins. Leave the daemon as
   the system treats any service.
3. No policy. Rejected: the plugins are the extension point, and the resolver
   and the MCP server are the parts an attacker reaches.

## Decision

Option 2, on both systems, with the same shape:

- **Resolver:** its own directories, port 53 on loopback, outbound TLS, no exec.
- **MCP server:** its own directories, the control socket, a listening TCP
  socket. It cannot apply a change; neither can the policy let it.
- **Plugins:** read the system, keep their own socket, write nothing, run
  nothing but the package manager's query for the update check. Not the
  person's private keys (AppArmor denies `.ssh` and `.gnupg` explicitly).
- **Daemon:** under AppArmor, a profile whose write rules and command list are
  generated from the plugin manifests at stage time, so a new plugin path is
  one place to change. Under SELinux it stays in the system's service domain;
  its authority is already limited by plans, snapshots, polkit and the
  manifests' allow-lists, and a policy that lists every file it may repair
  would add no protection the manifests do not already give.

AppArmor profiles are attached by the units (`AppArmorProfile=`, with a dash
so a machine without AppArmor ignores it), not by program path, so a program
a person starts themselves is not confined (the MCP server run by an
assistant's client over stdio, for one). The SELinux domains are entered by
the system's usual transition from `init_t`.

Both are packaged apart from the main package (`ibexwall-apparmor` for Debian
and Ubuntu, `ibexwall-selinux` for Fedora and the like) and removed with it.

## Consequences

- The update check on Fedora asks `dnf5` for a cache-only answer, which
  touches the RPM database's journal files; the plugin domain may write those
  (and map them), not create or remove anything in the database.
- Debian's cloud image does not boot with AppArmor enabled; the package
  installs the profiles and the system loads them when it does. They were
  exercised on Ubuntu 24.04 and 26.04, and the SELinux module on Fedora, each
  under enforcement with no denial for the whole workload (every plugin
  checked, changes made and undone, the resolver answering, the MCP server
  answering a request).
- Arch ships neither by default; no policy is shipped there.
- New plugin behaviour that needs more shows up as a denial in the matrix
  (`--phase f10`), and the fix is a rule with a reason, not a wider domain.
