<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# OpenVPN profiles IbexWall imports

`ibexctl plan net.vpn --set action=import --set name=work --set-file profile=work.ovpn`
turns a `.ovpn` file into a NetworkManager profile. It needs NetworkManager's
OpenVPN plugin (IbexWall installs nothing). Every directive is accepted and
mapped, ignored as harmless, or refused by name: a profile never imports with
a security setting silently dropped.

Accepted and mapped: `client`, `dev tun`, `proto udp|tcp`, up to four
`remote host [port] [proto]`, `remote-cert-tls server`, `cipher`,
`data-ciphers`, `auth` (SHA256, SHA384, SHA512), `tls-version-min` (1.2, 1.3),
`key-direction`, bare `auth-user-pass` (NetworkManager asks at connect time;
nothing is stored), and the inline blocks `<ca>`, `<cert>`, `<key>`,
`<tls-crypt>`, `<tls-auth>`. An encrypted key is asked for at connect time.

Ignored, because they change nothing an import carries: `nobind`,
`persist-key`, `persist-tun`, `resolv-retry`, `verb`, `mute`,
`mute-replay-warnings`, `auth-nocache`, `remote-random`,
`explicit-exit-notify`, `keepalive`, `ping`, `ping-restart`, `float`.

Refused, with the reason in the message: anything that runs a command or
loads code (`up`, `down`, `route-up`, `script-security`, `plugin`,
`tls-verify`, `setenv`, `learn-address`, `client-connect`, `ipchange`),
`management`, proxies, `compress` and `comp-lzo` (compression has been used
to attack encrypted tunnels), `pkcs12`, `dh`, `secret`, `route`,
`redirect-gateway`, `ifconfig`, `connection` blocks, `dev tap`, weak ciphers
(`none`, `BF-*`), `auth` below SHA256, `tls-version-min` below 1.2, file
references for certificates, keys and logins (paste them inline), and any
directive not listed above.

What is written: the certificates and keys under
`/etc/ibexwall/vpn/openvpn/<name>/` (keys 0600), the NetworkManager keyfile
(paths only, no secrets), and a record without secrets that the kill switch
reads. The private key and `tls-crypt` key are never shown in a preview.
The kill switch needs the server as an address: set `endpoints=IP:PORT` when
the profile names it by host name.
