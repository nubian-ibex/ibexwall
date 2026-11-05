<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0040: OpenVPN profiles are imported as a documented subset

Status: accepted 2026-11-04. The maintainer chose option 2 (a documented subset)
after F9 shipped with option 1. Phase: F9, completed after acceptance.

## Context

The spec asks `net.vpn` for "WireGuard/OpenVPN via NetworkManager" with
profile import. WireGuard is built into NetworkManager and a `wg-quick` file
maps almost one to one onto a keyfile. OpenVPN does not: NetworkManager needs
its separate OpenVPN plugin, a `.ovpn` file is a loose list of directives
(`remote`, `proto`, `cipher`, `tls-auth`, inline `<ca>`/`<cert>`/`<key>`
blocks, `auth-user-pass`, scripts) that only partly has an NM equivalent, and
the translation silently drops what NM cannot express, which for a security
tool is a risk of its own (a profile that "imports" without its `tls-crypt`).
No OpenVPN server can be run in the test VMs without much more machinery.

## Options

1. Defer OpenVPN import; support WireGuard end to end; the kill switch works
   for any tunnel interface and server the person names (`tun*` is on by
   default), so an OpenVPN tunnel set up in NetworkManager by other means is
   protected. (Done in F9.)
2. Import a documented subset of `.ovpn` (remote, proto, ca/cert/key inline
   or by path, cipher, tls-auth/tls-crypt, auth-user-pass by reference) and
   refuse everything else by name. About 400 lines and tests on sample
   profiles, plus a VM scenario with an OpenVPN server in a namespace.
3. Call `nmcli connection import type openvpn file X`, letting NetworkManager's
   own importer do the translation. Needs the `exec` op with a path argument
   (today exec arguments are fixed), and the importer's own gaps remain.

## Recommendation

Option 1 now, option 2 in a follow-up phase when a test server can be built:
refusing what cannot be expressed is the behaviour this project wants, and
option 3 would need a variable-argument exec that weakens the op allowlist.

## Outcome

Option 2 was built (`plugins/net.vpn/src/openvpn.rs`, documented in
`docs/openvpn-subset.md`). It is verified on five distros against a real
OpenVPN server in a namespace: NetworkManager takes the profile, the tunnel
carries traffic, the kill switch leaks nothing with the tunnel down and the
tunnel reconnects under it, and the rollback removes the files and the
profile. WireGuard was already supported end to end.
