<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# v1.0 release checklist

What version 1.0 requires, from the specification's F10 deliverables and
acceptance criteria, and where each item stands. Checked off items are done
and verified by the test battery and the VM matrix; open items need the
maintainer or a decision.

## Deliverables

- [x] SELinux module and AppArmor profiles, with the resolver, the MCP server
      and the plugins confined. Packages `ibexwall-selinux` and
      `ibexwall-apparmor`, enforced in the matrix.
- [x] Signing, SBOM and provenance: `cargo xtask release` signs the artifacts,
      writes a CycloneDX bill of materials and an in-toto SLSA statement;
      `verify-release` checks them.
- [x] Reproducibility check: `cargo xtask repro` builds twice and compares
      (192 files identical).
- [x] `ibexwall-docs` with a reference generated from the code (CLI, varlink,
      schemas, plugin catalog, MCP tools, decisions).
- [x] `ibexwall-website` in English, Portuguese, Spanish, French and German,
      with one page per hardening setting.
- [x] `ibexwall-plugin-index` with schema, generation and CI.
- [x] This checklist.
- [ ] Packages in COPR, PPA, OBS and AUR. Written and ready, but publishing
      needs the maintainer's accounts on each and the official release key.

## Acceptance

- [x] Install, upgrade and remove across the matrix with no residue, restoring
      the system: `cargo xtask vm-test --phase f10` on Fedora, Ubuntu 24.04 and
      26.04, Debian and Arch installs the packages built on the machine, uses
      them, upgrades, removes and purges, and checks no unit, process, file or
      kernel setting is left.
- [x] A smoke of the earlier phases against the installed packages (M8): F2
      checks, F7 notes, a real F3 DNS query and rollback, an F8 MCP request,
      and the history and audit chain.
- [x] Docs and site deploy: ibexwall.com and docs.ibexwall.com are live on
      Cloudflare Pages. Preview deploys per pull request are not wired yet:
      the sites are built and checked in CI, and the Pages projects exist, but
      production deploys are manual (`wrangler pages deploy`) until the git
      integration is connected.
- [x] Lighthouse 95 or more: 100 on the six heaviest pages.
- [x] `systemd-analyze security` documented for every unit
      (`docs/systemd-security.md`, and in the docs reference).

## Before a real tag

- [ ] The maintainer's release public key in `packaging/release.pub` and the
      signing secret in the `RELEASE_SIGNING_KEY` repository secret; without
      them the release workflow refuses to run.
- [ ] The three new repositories (`ibexwall-website`, `ibexwall-docs`,
      `ibexwall-plugin-index`) made public, after a review.
- [ ] The GitHub org domain verification clicked in the org Pages settings
      (the TXT record is already in DNS).
- [ ] Manual runs on Omarchy and EndeavourOS, and with real AI assistant
      clients (deferred by the maintainer).
- [ ] The from-source package builds (spec, `debian/`, PKGBUILD) exercised on a
      builder with the toolchain and `bpf-linker`; the test packages are built
      from the staged tree, and the release ships the prebuilt eBPF object for
      this.
- [ ] Email Routing for `security@ibexwall.com`, if wanted, with a destination.

## Out of scope for v1.0

The Modo Gerenciado contracts, the compliance profiles, and the closed plugin
are F11 (v1.1). OAuth for the MCP server, Windows and macOS, and new plugins
are out of scope for F10.
