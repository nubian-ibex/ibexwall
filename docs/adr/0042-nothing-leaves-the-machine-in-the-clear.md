<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0042: Nothing leaves the machine in the clear

Status: accepted 2026-11-04 (the maintainer: end-to-end encryption on every
channel that leaves the machine). Phase: F8 and F9 follow-ups, applies to F10
and F11.

## Context

The local interfaces (the core's Unix socket, the plugin sockets) never cross
a network. Everything that does cross one is a decision this project makes,
and "end to end" has a precise meaning: only the two ends can read it, and no
relay, proxy or middlebox in between can.

## The channels, and what holds today

- **DNS upstream.** DoT, DoH, DoH3 and DoQ only, with the certificate name
  checked. A plain upstream exists only for a resolver on the machine's own
  networks (private, loopback, link-local, ULA, CGNAT ranges) and is refused
  for any public address at plan time and at resolver start; the person is
  told when one is in use. Verified in the VM (F3 scenario d11).
- **Block-list and endpoint-list downloads.** HTTPS only, through rustls; a
  non-HTTPS list URL is refused.
- **MCP over HTTP.** TLS only (1.2 and 1.3): no plain mode exists, a key file
  readable by others is refused, access needs a user-chosen or generated
  Bearer token whose hash is kept. The traffic is encrypted between the
  assistant's client and `ibexwall-mcp` and nowhere else terminates it, as
  long as the person does not put a TLS-terminating proxy in front (the
  config command says so). What the assistant does with the answers (a hosted
  model) is outside this project; redaction and scopes limit what it sees.
- **Local MCP (stdio).** No network.
- **Plugin and update downloads.** HTTPS for confidentiality plus signatures
  (minisign or ed25519) for integrity; to be built with the plugin index
  (F10).
- **Reports and exports (F11 and the exporters).** Network destinations
  require TLS (syslog over TLS, OTLP over TLS, webhooks over HTTPS);
  plaintext is accepted only for a loopback or Unix-socket sink.
- **Managed mode (F11, the closed plugin).** mTLS between device and server
  as the transport, and the report itself sealed to the organization's key
  (HPKE, RFC 9180, to a key delivered with the policy bundle) so a
  load balancer or CDN that terminates TLS still cannot read it. The report
  schema has no browsing history, DNS, files, screen or keystrokes at all.

## Decision

1. No code path sends data over a network in the clear. New outbound or
   listening sites are added to a guard (`xtask/src/egress.rs`) on purpose: it
   fails the build on a plaintext `http://` address in production code, on an
   unexpected network listener, and on a plain mode in the MCP transport.
2. TLS minimum 1.2, 1.3 preferred; certificates are checked against the
   system store, the bundled roots (DNS upstreams) or a pinned certificate
   (MCP self-signed, pinned by its SHA-256 fingerprint on the client).
3. Secrets travel in headers from the environment or a prompt, never in a
   URL, a file that is committed, or a log. Tokens are stored as Argon2id
   hashes.

## Not covered

- What a remote model provider does with what the assistant sends it.
- Metadata (who talks to whom, when, how much); only content is protected.
- A person who terminates TLS on purpose in front of the MCP server.
