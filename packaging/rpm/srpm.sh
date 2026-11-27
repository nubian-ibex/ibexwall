#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Makes the source RPM that COPR builds, from the published release of the
# version in ibexwall.spec: its source archive and its three RPMs, believed
# only if the release key signed their checksums. Needs curl, minisign and
# rpm-build. Usage: sh packaging/rpm/srpm.sh OUTDIR

set -eu

[ $# -eq 1 ] && [ -n "$1" ] || { echo "usage: $0 OUTDIR" >&2; exit 2; }
mkdir -p "$1"
outdir=$(cd "$1" && pwd)
packaging=$(cd "$(dirname "$0")/.." && pwd)
spec=$packaging/rpm/ibexwall.spec
version=$(sed -n 's/^Version:[[:space:]]*//p' "$spec")
url=https://github.com/nubian-ibex/ibexwall/releases/download/v$version

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
    curl -fsSL --retry 3 -o "$work/$1" "$url/$1"
}

fetch SHA256SUMS
fetch SHA256SUMS.minisig
minisign -V -q -p "$packaging/release.pub" -m "$work/SHA256SUMS"

# Fetches the one file the signed list names that matches $1, checks it, and
# keeps it as $2.
source_file() {
    name=$(awk -v re="^$1\$" '$2 ~ re { print $2 }' "$work/SHA256SUMS")
    if [ -z "$name" ] || [ "$(printf '%s\n' "$name" | wc -l)" -ne 1 ]; then
        echo "SHA256SUMS of v$version does not name exactly one file like $1" >&2
        exit 1
    fi
    fetch "$name"
    (cd "$work" && awk -v name="$name" '$2 == name' SHA256SUMS | sha256sum -c --quiet -)
    [ "$name" = "$2" ] || mv "$work/$name" "$work/$2"
}

# The version as a regular expression: its dots are literal.
v=$(printf '%s' "$version" | sed 's/[.]/[.]/g')
source_file "ibexwall-${v}[.]tar[.]gz" "ibexwall-$version.tar.gz"
for pkg in ibexwall ibexwall-desktop ibexwall-mcp; do
    # The release's file name carries the dist tag of the machine that built it.
    source_file "$pkg-${v}-1[.].*[.]x86_64[.]rpm" "$pkg-$version.release.rpm"
done

# A define on this command line would not reach the builder that rebuilds the
# source RPM, so the mode is written into the spec it carries.
{
    echo '%global from_release 1'
    cat "$spec"
} >"$work/ibexwall.spec"
rpmbuild -bs --define "_sourcedir $work" --define "_srcrpmdir $outdir" "$work/ibexwall.spec"
