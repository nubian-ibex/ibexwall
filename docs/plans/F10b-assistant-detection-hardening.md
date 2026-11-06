<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F10b: connect an assistant, detect the current setup, a Hardening section

Requested by the maintainer on 2026-11-05 after running the app. It runs
alongside F10 (packaging stays M4 onward) and follows the order the maintainer
chose: 1 connect an assistant, 2 detection with pre-filled settings, 3 the
Hardening catalog and the new tool plugins.

Status: parts 1, 2 and 3 done 2026-11-05, including the rkhunter and chkrootkit, OpenSCAP and local-exposure (nmap) plugins. Left: the ssh, sysctl and MAC pre-fill, and dedicated screens for the three scanners (they show in the plugin detail for now).

## Rules that do not change

Plugins propose and the core executes; nothing is applied without a plan, a
snapshot, an approval and a tested rollback. IbexWall installs no software: for
a tool that is missing it shows the distro's own command for the person to run.
The MCP never applies anything. No telemetry. External facts are checked
against the official source and cited; licensed texts (CIS) are referenced by
id and link, never copied.

## 1. Connect an assistant (gap in F8)

The Assistant screen gains a "Connect an AI" section: pick the client (Claude
Code, OpenCode, VS Code), copy the exact snippet (what `ibexctl mcp config`
prints), and, for access from another machine, turn the HTTPS transport on.

Design: a new control plugin `system.assistant` owns `/etc/ibexwall/mcp.toml`
and `/etc/ibexwall/mcp/`. Its plan writes the `[http]` section and `[[token]]`
blocks through the normal flow, so enabling remote access is reviewed,
approved and reversible like any other change. The token secret is generated
where the person is (the UI or `ibexctl`), shown once, and only its Argon2id
hash goes into the plan; the plan and the log never hold the secret. The
screen lists tokens (name, client, expiry, last use from the audit chain),
revokes one (a plan that removes its block), shows the certificate fingerprint
and `ibexctl mcp config --url` for the remote form.

Open question for the maintainer, in the ADR: whether the grants of a client
(`[[client]]` scopes) are editable in the UI or only chosen from the three
presets (read, read and plan, read plan and propose). Recommendation: presets
only in v1.0.

Verify: unit tests for the plan; UI tests; a VM scenario that enables the
transport through the plan, connects with a token, revokes it and rolls back.

## 2. Detect what is already there and pre-fill

Each plugin's check also reports a "starting point": what it found installed
and active, what it suggests and the values that fill its form. Information
and suggestions, never failures.

- DNS: the resolver in use (systemd-resolved, NetworkManager, dnsmasq,
  unbound), where it points, whether it is encrypted; the network's servers
  (already reported) offered as one-click servers.
- Time: chrony, systemd-timesyncd or ntpd; whether NTS is on; suggest chrony
  with NTS where chrony is installed.
- Firewall: firewalld, ufw, nftables rules of others or nothing active; if
  nothing is active, suggest starting or configuring one.
- SSH, sysctl, MAC (SELinux or AppArmor): current effective values prefill the
  form so a change shows as a diff against what is there.

Contract: an optional `detected` object in the check report (versioned schema,
`cargo xtask schemas`), rendered by the UI as "We found..." with a button that
fills the form. Verified in the VM against each distro's real defaults.

## 3. Hardening section

A catalog of recommendations, versioned in the repository, each with: id, a
title and summary in en and pt-BR, the source (name, URL, section) , what it
changes (typed ops through an existing plugin), what it can break, the risk
level, whether it is reversible, the detection of "already applied", and a link
to the page on the site that explains it (the domain is a setting until P-01).
The screen groups by area (kernel, boot, network, accounts, filesystem,
privacy), shows applied and not applied with the evidence, and builds one plan
from the items the person ticks. Items that can break a working system
(module signing, disabling USB, `nosuid` on home) are never pre-ticked.

Initial sources, as the maintainer chose: the madaidans Linux hardening guide
(licence checked before any text is reused; the catalog states each item in its
own words and cites the section), KSPP recommended settings and the kernel
documentation, CIS Benchmarks (identifiers and links only), ANSSI-BP-028 and
Kicksecure. Every item is checked on the five distros before it ships; an item
that a distro breaks is marked as such for that distro.

New tool plugins (detect, show the install command, run on request, turn the
report into findings): `endpoint.rootkit` (rkhunter and chkrootkit),
`system.openscap` (profiles such as CIS, STIG, ANSSI; results by rule) and
`net.exposure` (nmap against this host only, `127.0.0.1` and its own
interfaces; scanning other machines is out of scope). Lynis, ClamAV and AIDE
are already integrated.

## What F11 (managed mode) still needs

Recorded for the maintainer's question, not built here: device enrolment and
identity (mTLS with rotation and revocation), signed and versioned policy with
rollback, the report sealed to the organization's key (ADR-0042), local consent
and the right to refuse, a signed posture attestation, a reference server and a
console outside the open repository, and a test that breaks the build if a
forbidden field (browsing, DNS, files) appears in a report.

## Order and checks

1, then 2, then 3, each ending with the battery and the five-distro phases
green and signed commits. Out of scope: OAuth, editing client scopes freely in
the UI, scanning other hosts, installing any tool.

## Part 3 as built

The catalog is `catalog/hardening.json`. The `system.hardening` plugin and the
interface both read that one file, so what the screen offers and what the
machine is judged against cannot drift. Each item carries a bilingual title and
summary in our own words, what it can break, its sources (guide, section, link),
a probe (sysctl values, module groups or a mount option) and the change that
applies it through the plugin that owns it (`system.sysctl`, `system.modules`,
`system.mounts`). Tests keep the catalog honest: every item is sourced and
translated, a risky item states what it breaks, no high-risk item is pre-ticked,
every patch is accepted by its plugin and matches its probe.

Sources used so far: the Linux Hardening Guide (madaidans) sections 2.2, 2.5.2
and 17, the Linux kernel documentation, and ANSSI-BP-028 as a general reference.
KSPP and CIS were not used: the KSPP page could not be fetched when the catalog
was written, and CIS text is licensed (ids and links only, when added). The
madaidans page shows no licence, so nothing is copied from it.

The explanation pages on the site are linked once the domain is set
(`ui/src/lib/site.ts`).

## The scanner plugins as built

`endpoint.rootkit`, `net.exposure` and `system.openscap` share one shape
(`ibexwall_sdk::scanner`): the plan writes a oneshot unit (and a timer on
request) that runs the outside tool as root over a read-only system and leaves
its report in `/var/lib/ibexwall/<tool>/`; the check reads that report back.
The plugin never runs the tool and never installs it; a missing tool is
reported with the distribution's own install command.

- Rootkit: rkhunter warnings and chkrootkit `INFECTED` lines are leads, capped
  at 20, and weigh as one low-severity check because both tools raise false
  alarms. The unit sees the real `/dev` and `/tmp`.
- Exposure: nmap runs against this computer's own IPv4 addresses, read from
  `/proc/net/fib_trie` at plan time; the config has no field for a target.
  Seen from the machine itself it does not show what a firewall blocks from
  outside, and the text says so. Fedora runs nmap in its own SELinux domain
  (`traceroute_t`), which is refused under `NoNewPrivileges` and may not write
  to IbexWall's state directory, so this unit lifts `NoNewPrivileges` and has
  systemd store nmap's standard output.
- OpenSCAP: the data stream is chosen from the distribution (never a free path)
  and the profile must exist in it. Verified end to end on Fedora. Ubuntu 24.04
  and Debian ship no content for their release (Ubuntu 24.04's `ssg-debderived`
  has content up to 22.04), so there the plugin says so and plans nothing.
  Arch has no content package.
- `systemd-analyze security` rates the root scanners poorly (rkhunter 9.0,
  OpenSCAP 8.2): they must read most of the system. The units keep the system
  read-only and write only to their own state directory.
