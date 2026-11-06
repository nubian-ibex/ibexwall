# SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Two ways to build:
#   from source:   rpmbuild -ba ibexwall.spec   (runs `cargo xtask stage`)
#   from a staged tree, as CI does for a release it has already built:
#   rpmbuild -bb --define 'prebuilt_stage /path/to/stage' ibexwall.spec
# The stage directory holds `root/` (the installed layout) and `stage-lists/`
# (which package owns which file); see `cargo xtask stage`.

%global debug_package %{nil}
%global __strip /bin/true

Name:           ibexwall
Version:        0.1.0
Release:        1%{?dist}
Summary:        Security center for Linux
License:        GPL-3.0-or-later
URL:            https://github.com/nubian-ibex/ibexwall
%{!?prebuilt_stage:Source0: %{name}-%{version}.tar.gz}
%{!?prebuilt_stage:BuildRequires: cargo, rust, systemd-rpm-macros}
BuildRequires:  systemd-rpm-macros
Requires:       nftables
Requires:       polkit
Requires:       systemd
Suggests:       chrony
Suggests:       firewalld

%description
IbexWall shows how secure a Linux computer is, explains what to fix, and fixes
it with changes you review first and can undo. This package holds the daemon,
the command line, the resolver and the plugins; nothing it does is applied
without a plan, a snapshot and your approval.

%package desktop
Summary:        IbexWall desktop app and session agent
Requires:       %{name} = %{version}-%{release}
Requires:       webkit2gtk4.1
Requires:       gtk3
Recommends:     libayatana-appindicator-gtk3

%description desktop
The IbexWall window and tray icon, and the agent that asks you about a held
connection.

%package mcp
Summary:        IbexWall MCP server for AI assistants
Requires:       %{name} = %{version}-%{release}

%description mcp
The MCP server that lets an AI assistant read your security status and
suggest changes. It can never apply one. The HTTPS mode is off until you
turn it on.

%prep
%if 0%{!?prebuilt_stage:1}
%autosetup
%endif

%build
%if 0%{!?prebuilt_stage:1}
cargo xtask stage --destdir %{_builddir}/stage/root
%endif

%install
%if 0%{?prebuilt_stage:1}
stage=%{prebuilt_stage}
%else
stage=%{_builddir}/stage
%endif
# Only what each RPM package owns: the staged tree also holds the AppArmor
# profiles, which are for Debian and Ubuntu.
for pkg in ibexwall ibexwall-desktop ibexwall-mcp; do
    sed 's#^/##' "$stage/stage-lists/$pkg.list" | tar -C "$stage/root" -cf - -T - | tar -C %{buildroot} -xf -
    { sed 's/^/%dir /' "$stage/stage-lists/$pkg.dirs"; cat "$stage/stage-lists/$pkg.list"; } > %{_builddir}/$pkg.files
done

%files -f %{_builddir}/ibexwall.files
%files desktop -f %{_builddir}/ibexwall-desktop.files
%files mcp -f %{_builddir}/ibexwall-mcp.files

%post
. /usr/lib/ibexwall/package-scripts.sh
post_install

%preun
. /usr/lib/ibexwall/package-scripts.sh
# $1 is how many copies stay installed: 0 is a removal, 1 an upgrade.
if [ "$1" -eq 0 ]; then
    pre_remove
fi

%postun
# The scripts file belongs to this package, so after a removal it is gone.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
if [ "$1" -ge 1 ]; then
    . /usr/lib/ibexwall/package-scripts.sh
    post_upgrade
fi

%changelog
* Thu Nov 05 2026 Nubian Ibex <maintainers@nubian-ibex.invalid> - 0.1.0-1
- First package.
