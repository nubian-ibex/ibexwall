<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Releases: what is published, and how to check it

A release is a set of files and the proof of where they came from. Nothing is
published until a maintainer pushes a tag; the workflow builds a draft that a
person then reviews.

## What a release holds

- `ibexwall-VERSION.tar.gz`: the source at the tagged commit.
- `ibexwall-VERSION-x86_64-linux.tar.gz`: the installed layout, which the
  RPM, DEB and Arch packages are made from (`cargo xtask stage`).
- `ibexwall-ebpf-VERSION.o`: the compiled eBPF programs, so a package build
  needs neither the nightly compiler nor `bpf-linker`.
- `ibexwall-VERSION.cdx.json`: the software bill of materials (CycloneDX 1.6):
  every Rust crate the binaries are built from, with the checksum of its
  source and its license, and the JavaScript packages the interface bundles.
  Packages only the tests use are left out.
- `ibexwall-VERSION.intoto.json`: an in-toto statement with a SLSA
  provenance predicate: the files and their digests, the commit, the digests
  of `Cargo.lock`, `pnpm-lock.yaml` and the toolchain file, the compiler
  version and whether the working tree was clean. A build on a maintainer's
  machine says `local` as its builder; the workflow says which workflow ran.
- `SHA256SUMS`, and a `.minisig` signature for every file and for the sums.
- `ibexwall-release.pub`: the public key, the one the daemon embeds.

The workflow also asks GitHub for its own attestation of the archives, which
`gh attestation verify` checks against the repository and the workflow.

## Checking a release

With a checkout of the source, and the files in a folder:

```sh
cargo xtask verify-release DIR DIR/ibexwall-release.pub
```

It checks the signature of `SHA256SUMS` first, then every checksum, then the
signature of every file. Any one failing stops it with the name of the file.
The files are in the minisign format, so `minisign -V -p ibexwall-release.pub
-m FILE` does the same for one file. Check that `ibexwall-release.pub` is the
key published at <https://ibexwall.com/security> before trusting what it
signed.

The plugin manifests in an installed package are signed by the same key, and
the daemon refuses a manifest that does not verify.

## Reproducing the build

`cargo xtask repro` builds the installed layout twice from copies of `HEAD` in
different directories, with the commit's timestamp and the source paths
rewritten, and compares every file. The tarballs are made with a fixed order,
owner and time, so the same tree gives the same bytes.

## The key

The release key is the maintainer's. Its secret half is never in the
repository; the workflow reads it from a repository secret and deletes it when
the build is done. Until the maintainer supplies the official key the packages
the matrix builds are signed with the development key, and the workflow stops
if `packaging/release.pub` is missing.

## Build type

`https://github.com/nubian-ibex/ibexwall/blob/main/docs/release.md#build-type`
names the build described above: `cargo xtask release` on the toolchain in
`rust-toolchain.toml`, with the locked dependencies and no network access to
anything but the registry's crates.

## From a release to the package repositories

The release packages feed the package repositories. Both paths below work from
a published release, check its signature first, and push nothing: what a
maintainer does with their output is listed in `docs/release-checklist.md`.

The AUR: `cargo xtask aur --version V [--pkgrel N] [--out DIR]` writes an
AUR-ready directory (`PKGBUILD`, `.SRCINFO`, the install script) whose packages
repack the files of the release's Arch packages, which the PKGBUILD downloads
and checks against the release's signed checksums. The version and every
checksum come from the signed `SHA256SUMS`, so the directory cannot name
artifacts the release does not hold. The maintainer reviews the directory and
pushes it to the AUR (`ibexwall-bin` and friends); the VM phase
`cargo xtask vm-test --distro arch --phase aur` does in a VM what a user does:
`makepkg`, the diff against the release's packages, install, the daemon's
answers and removal.

COPR: the same repository holds `.copr/Makefile` and `packaging/rpm/srpm.sh`,
which are the "make srpm" source method COPR can be pointed at. COPR runs the
Makefile in a Fedora chroot; it fetches the release's source archive and its
three RPMs, checks the signed checksums with the release key in the
repository, and makes a source RPM whose build unpacks those packages and
repackages them, so the builder compiles only the SELinux policy. A release
signed by another key is refused. The source RPM then builds in COPR's chroots
without network access, and each chroot stamps its own dist tag, so users of
every Fedora release get packages tagged for it. The VM phase
`cargo xtask vm-test --distro fedora --phase copr` runs the same steps under
`mock`, including a build for the previous Fedora release and a refusal with a
foreign key.

Because the payload is the release's, a repository build is an attested
repackaging, not a from-source build. A from-source COPR build would need the
nightly toolchain, `bpf-linker` and the eBPF object on the builder; until that
is realistic, the from-source spec path (`rpmbuild -ba`) remains the way a
distribution packager builds from source, and the release packages stay the
source of truth for what reaches the repositories.

