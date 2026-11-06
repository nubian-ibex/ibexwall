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

From source, on the target distribution:

- `rpm/ibexwall.spec`: `rpmbuild -ba rpm/ibexwall.spec` (runs `cargo xtask stage`).
- `deb/debian/`: copy `deb/debian` next to the source as `debian/` and run
  `dpkg-buildpackage -b -us -uc`.
- `arch/PKGBUILD`: `makepkg` in `packaging/arch`.

From a tree a release has already built, which is how CI packages a release
and how the VM matrix tests the packages: set the staged tree with
`--define 'prebuilt_stage DIR'` (rpm) or `IBEXWALL_STAGE=DIR` (deb, arch). The
from-source builds are the shape the COPR, PPA, OBS and AUR builds will use;
they are not exercised here, because they need the toolchain and the eBPF
object (`cargo xtask ebpf`, nightly Rust and `bpf-linker`) on the builder.

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
- `rpm/`, `deb/`, `arch/`: the three formats.
- `scripts.sh`: the install, upgrade and removal steps.

SELinux and AppArmor policy come with M5, and signing, the SBOM and
reproducibility with M6 (`docs/plans/F10-packaging-release.md`).
