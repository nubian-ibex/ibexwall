<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F10: packaging, release, docs and site (toward v1.0)

Goal: someone on Fedora, Ubuntu, Debian or Arch can install IbexWall from a
package, update it, remove it and get the machine back as it was; the project
has generated documentation and a site; and a v1.0 release can be cut from a
checklist. Spec phase F10; the maintainer said "siga para a F10" on
2026-11-05 and accepted ADR-0041 (official plugins as one multicall binary).

Status: in progress (autonomous mode). M2 done 2026-11-05: 26 official plugins in
one `ibexwall-plugins` binary (9.2 MiB stripped, from 58 MiB over 31), phases
f1 to f9 green on all five distros.
M4 done 2026-11-06: RPM, DEB and Arch packages (ibexwall, ibexwall-desktop,
ibexwall-mcp) from one staged tree (`cargo xtask stage`), the release key
embedded in the daemon, `ibexwalld --cleanup` for the uninstall, and a VM phase
(`--phase f10`) that builds, installs, uses, upgrades, removes and purges on
five distros with no residue. COPR, PPA, OBS and AUR publishing need the
maintainer's accounts and keys. `docs/systemd-security.md` rates every unit.
M3 done 2026-11-05 (ADR-0043): every plugin runs in its own socket-activated,
sandboxed unit (dynamic user, manifest capabilities, systemd exposure 1.6 to
1.8); phases f1 to f9 green on five distros. The F9 limits on /home and kernel
modules are lifted.
M1 done 2026-11-05: `unwrap` denied in production code (mutex locks say
`lock poisoned`, one real unchecked parse fixed), the five largest files split
(now all under 800 lines; what remains over 600 are the e2e tests, the eBPF
loader, `nft.rs`, `ops.rs`), `cargo doc` clean with warnings denied, and CI
jobs for docs, UI and a coverage report (unverified until they run on GitHub).

## What I can and cannot do alone

I can write, build and test everything locally and in the VMs: the packages,
the install, update and removal matrix, the policies, the generated docs and
the site sources. I cannot publish: COPR, the PPA, OBS and the AUR need
accounts, and signing needs the official release key and the plugin trust
anchor, which only the maintainer should hold. The domains (P-01) are
undecided, so the site and the docs are built with the domain as a setting.
Creating repositories in the organization (`ibexwall-docs`,
`ibexwall-website`, `ibexwall-plugin-index`) is outward-facing, so I will ask
before doing it; until then they live as directories under `docs/` and `site/`
ready to move.

## Milestones

M1 Maintainability pass (before adding more): split the files over 600 lines
(`ibexctl` main, the engine, `net.vpn`, `api.rs`, `net.dns`), fewer
`unwrap` and `expect` in production paths, clippy beyond `all` where it is
cheap, and the CI gaps (a UI job, `cargo doc`, a coverage report). Behaviour
unchanged: the existing tests are the proof.

M2 Multicall plugins (ADR-0041) and a size-minded release profile: plugin
crates become libraries with `run()`, one `ibexwall-plugins` binary dispatches
on argv[0], the packages ship it with a link per plugin; release profile with
strip and LTO. Measure before and after.

M3 A unit per plugin: the supervisor starts each plugin in its own transient
unit with the sandbox its manifest asks for (today they are children of the
daemon and inherit its sandbox, which hides `/home` and `/usr/lib/modules`
from the integrity, persistence and antivirus plugins). This lifts the limits
recorded in the F9 report.

M4 Packages: RPM (COPR), DEB (PPA and OBS), PKGBUILD (AUR), split into
`ibexwall` (daemon, CLI, plugins, units, polkit, sysusers, tmpfiles),
`ibexwall-desktop` and `ibexwall-mcp`. Install, upgrade and removal leave no
residue and restore what the plugins changed (the 4.15 failure and
uninstall modes of the spec).

M5 Mandatory access control: an SELinux policy module and AppArmor profiles
for the daemon, the resolver, the plugin units and the MCP server.

M6 Supply chain: signing of artifacts and plugin manifests (official key
supplied by the maintainer; a test key until then), SBOM (CycloneDX),
provenance (SLSA-style attestation from CI), and a reproducibility check
that builds twice and compares.

M7 Docs and site: `ibexwall-docs` with reference generated from the code
(CLI, varlink IDL, schemas, plugin catalog and messages, `mcp.toml`),
`ibexwall-website` (en and pt-BR complete, de, fr, es with structure) and
`ibexwall-plugin-index` (structure and CI), all buildable offline; Lighthouse
checked locally.

M8 Matrix test: `cargo xtask vm-test --phase f10` installs the built packages
on the five distros, runs a smoke of each earlier phase against the installed
system, upgrades, removes, and diffs the machine against a snapshot taken
before; `systemd-analyze security` is recorded for every unit.

M9 The v1.0 release checklist, report, STATUS, threat-model update.

## Order

M2 first (it is decided and changes how everything is built), then M1 and M3 (they change the code the packages carry), then M4, M5,
M6 in parallel in spirit, M7 and M8, then M9. Each milestone ends with the
battery green and a signed commit.

## Out of scope for F10

The Modo Gerenciado contracts and the closed plugin (F11), OAuth for the MCP
server, new plugins, and Windows or macOS.

## Risks

- Per-plugin units change how every plugin is started; the five-distro phase
  suites (f1 to f9) are the regression net and run after M3.
- SELinux and AppArmor policies are easy to write too loose; the VM matrix
  runs enforcing, and the policies are reviewed against the threat model.
- Package scripts run as root on other people's machines: they stay minimal,
  declarative where the packaging format allows, and are tested for removal.
- Size targets are estimates until measured (M2).
