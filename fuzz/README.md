<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# fuzz

Planned cargo-fuzz targets for the parsers that face untrusted input:
varlink framing, the plugin manifest, the policy bundle, blocklists and
DNS messages, with a short nightly CI job (spec SEC-08).

Not implemented yet. The parsers are covered by unit and property tests
today, and the targets plus the nightly job land after v1.0, because
cargo-fuzz needs a nightly toolchain the release matrix does not use.
This is recorded in the F10c audit plan.
