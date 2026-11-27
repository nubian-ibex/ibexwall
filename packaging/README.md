<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# packaging

IbexWall ships as three packages on every family: `ibexwall` (the daemon, the
command line, the resolver, the plugins, the units, the polkit policy and the
users), `ibexwall-desktop` (the window, the tray and the session agent) and
`ibexwall-mcp` (the MCP server). The desktop and MCP packages depend on the
core one at the same version.

## One layout, three formats

`cargo xtask stage` lays IbexWall out as it is installed, under one directory,
and writes which package owns each file (`stage-lists/<package>.list`, and
`.dirs` for the directories only IbexWall uses). The RPM spec, the Debian
source package and the PKGBUILD are thin wrappers over that tree, so what is
installed is decided in one place. `stage` also:

- builds the release binaries with the release public key embedded
  (`IBEXWALL_RELEASE_PUBKEY`), so the installed daemon trusts exactly the
  plugins the package shipped and needs no `--dev-key`;
- signs each plugin manifest with the key in `--key-dir` (the development key
  by default; the maintainer's release key directory for a release);
- generates the socket and service unit of every plugin from its manifest
  (ADR-0043).

```sh
cargo xtask stage                       # target/stage/root and target/stage/stage-lists
cargo xtask stage --key-dir /path/keys  # sign with the release key (dev.pub, dev.key)
```

## Building a package

The RPM spec builds three ways:

- from source: `rpmbuild -ba rpm/ibexwall.spec` (runs `cargo xtask stage`);
- from a staged tree, as CI does for a release it has already built:
  `rpmbuild -bb --define 'prebuilt_stage DIR' rpm/ibexwall.spec`;
- from the published release packages, as COPR does: `rpm/srpm.sh` makes a
  source RPM from the release's archive and RPMs (it refuses anything the
  release key did not sign), and building that source RPM repackages them;
  see `docs/release.md`.

The Debian source package and the PKGBUILD build from source, on the target
distribution:

- `deb/debian/`: copy `deb/debian` next to the source as `debian/` and run
  `dpkg-buildpackage -b -us -uc`.
- `arch/PKGBUILD`: `makepkg` in `packaging/arch`.

From a tree a release has already built, which is how CI packages a release
and how the VM matrix tests the packages: set the staged tree with
`--define 'prebuilt_stage DIR'` (rpm) or `IBEXWALL_STAGE=DIR` (deb, arch). The
from-source builds are the shape the PPA, OBS and distribution builds use;
they are not exercised here, because they need the toolchain and the eBPF
object (`cargo xtask ebpf`, nightly Rust and `bpf-linker`) on the builder.

The package repositories are fed from the release instead: the AUR directory
comes from `cargo xtask aur` (a `-bin` package that repacks the release's
Arch packages), COPR from `rpm/srpm.sh` and `.copr/Makefile`. Both verify the
release's signature and push nothing; how they are checked in VMs is
`docs/release.md`, and what stays with a maintainer is
`docs/release-checklist.md`.

### The RPM dist tag

A package file name carries the dist tag of the machine that built it
(`ibexwall-0.6.0-1.fc45.x86_64.rpm`): rpmbuild takes it from the chroot or
system it runs on, and a release built on one builder cannot avoid it. This
matters only for the packages published in the release itself: everyone else
gets the tag of their own build. The repositories do not inherit it: COPR
builds once per chroot and each build is stamped with its own tag, and the
AUR installs the release's Arch packages, which have no dist tag. So the
release's RPMs are tagged for the builder's Fedora, and the repositories are
the way to install on any other Fedora release.

## What install, upgrade and removal do

All three formats run the same steps (`scripts.sh`, installed as
`/usr/lib/ibexwall/package-scripts.sh`):

- install: create the users and directories, switch on the control socket and
  every plugin's socket (a preset), and start them. The resolver, the
  connection monitor, the MCP server and the session agent stay off until used.
- upgrade: the same, then restart the daemon and the plugin services on the
  new files; the changes already made, the history and the firewall stay.
- removal: stop taking connections, run `ibexwalld --cleanup`, then stop and
  disable the units. Cleanup rolls back every change still in effect, newest
  first, through the snapshot each took (kernel settings, module blocks,
  drop-ins, units, browser policies, the firewall table) and removes what is
  left of IbexWall's nftables table. It never touches a table or a file that
  is not IbexWall's.
- purge (Debian and Ubuntu): also removes the user's data: the state, the
  audit chain and the settings under `/var/lib/ibexwall` and `/etc/ibexwall`.
  Fedora and Arch have no purge: those directories stay until deleted by hand.

The VM matrix (`cargo xtask vm-test --phase f10`) builds the packages on each
distribution, installs them, makes real changes, upgrades, removes, and checks
that no unit, process, file or kernel setting is left.

## Files

- `systemd/`: the units; the plugin units are generated.
- `polkit/`, `sysusers.d/`, `tmpfiles.d/`: what the daemon needs on the system.
- `desktop/`, `icons/`: the application entry.
- `rpm/`, `deb/`, `arch/`: the three formats; `arch/aur/` is the template
  `cargo xtask aur` renders, and `rpm/srpm.sh` is what COPR's
  "make srpm" method runs (`.copr/Makefile` calls it).
- `scripts.sh`: the install, upgrade and removal steps.

## Mandatory access control

`ibexwall-apparmor` (Debian and Ubuntu) and `ibexwall-selinux` (Fedora and the
like) confine the resolver, the MCP server and the plugins, and the AppArmor
profile of the daemon is generated from the plugin manifests. What is and is not
confined, and why, is ADR-0044. The AppArmor profiles live under
`/usr/share/ibexwall/apparmor` and are linked into `/etc/apparmor.d`; the
units ask for them with `AppArmorProfile=`, so a program a person starts
themselves is not confined. The SELinux module is built by the RPM from
`selinux/`.

## Supply chain

Signing, the SBOM, the provenance statement and the reproducibility check are
`cargo xtask release`, `verify-release` and `repro`; see `docs/release.md`.
