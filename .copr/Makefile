# SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# COPR "make srpm" source method: COPR runs this as root in a Fedora chroot
# with network access, then builds the source RPM in each chroot.

repo := $(dir $(lastword $(MAKEFILE_LIST)))..

.PHONY: srpm
srpm:
	dnf -y install curl minisign rpm-build systemd-rpm-macros
	sh $(repo)/packaging/rpm/srpm.sh "$(outdir)"
