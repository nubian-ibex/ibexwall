<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F11b: the managed-mode contracts

Requested by the maintainer on 2026-11-07, to run autonomously after
F10c closed. Status: approved to proceed (the maintainer set autonomous
mode for the phases ahead).

The open core gains everything the corporate plugin needs to manage a
machine without the core phoning home (spec §4.14, Appendices C and D):
a signed policy bundle verified in the core, org locks that already
work, an effective-config view, a report generator with a schema that
cannot carry sensitive data, and a signed break-glass code. The launch
strategy (planning/05, D-023..D-027) stays: this is the free core half;
enrollment, mTLS and the console belong to the closed plugin.

## What exists already

- `PolicyBundle` in `ibexwall-proto` with structural validation
  (schema, version, org id, lock patterns, timestamps).
- The `org` config layer with glob locks (`is_locked`), enforced on
  every plan and user-layer write since the F10c M3 work.
- JCS (RFC 8785) + ed25519 verification of the signed compliance
  export, in the core, with a tamper test.

## Milestones

1. M1 Bundle verification in the core. Load anchors from
   `/etc/ibexwall/trust/*.pub` (minisign public keys, same format as
   the plugin key); verify `JCS(bundle minus signature)` with the key
   named by `key_id`; refuse a wrong key, a bad signature, an expired
   bundle (`expires_at` in the past) and a version lower than the
   stored one (anti-rollback). Persist the accepted bundle (org layer
   settings, locks, version, org id) so it survives a restart and
   backs the rollback check. Verify: unit tests per refusal (bad
   signature, expired, rollback, unknown key) plus one round trip.
2. M2 The `com.ibexwall.Policy` interface and the local provider.
   `ApplyBundle` accepts a verified bundle and applies it as the org
   layer (a plan when settings touch plugins, or a direct layer write
   when they only set config); `GetEffective` returns config, locks and
   per-key sources. Both authorize via a dedicated polkit action
   (`com.ibexwall.policy.provider`, no default allow) and audit the
   actor. `ibexctl policy apply-bundle <file>` is the GitOps/Ansible
   path. Verify: e2e in the sandbox, `Locked` refused, audit rows.
3. M3 The report generator. `BuildReport(kind)` produces exactly the
   sections the bundle's `report.include` allows: posture, findings,
   package versions, blocked-connections summary, change audit. The
   report type (already in `ibexwall-proto/report.rs`) keeps no fields
   for browsing/DNS history, files, screen, passwords or keystrokes,
   and a test asserts the serialized shape. The last built report is
   stored and shown verbatim by the UI.
4. M4 Break-glass. `UseBreakGlass(code)` verifies a minisign signature
   over scope and expiry with the same anchors, refuses an expired or
   out-of-scope code, unlocks the named lock patterns until the expiry
   and writes an audit row. Verification is offline; nothing leaves the
   machine. Verify: expired, wrong-scope and valid codes in tests.
5. M5 The "Organização" screen (mockup 06). Shows the org identity, the
   locked keys with a padlock and "set by your organization", what the
   report includes and what never leaves, and the last report exactly
   as generated. Five languages, honest wording.
6. M6 `--phase f11b` on five distros: apply a bundle signed with a test
   key, see the locks refuse a user change, tamper with the bundle and
   see it rejected, use a break-glass code, roll the version back and
   see it refused. Docs: the managed-mode page in `ibexwall-docs`.

## Rules that do not change

- The core verifies everything itself; it never fetches a key, a bundle
  or a revocation list over the network.
- Protections are never disabled by inactivity or by the bundle
  expiring: an expired bundle keeps the last valid policy and only
  refuses a new one.
- No telemetry: the report leaves the machine only because the closed
  plugin (out of this repository) sends it, and its schema cannot carry
  browsing history, files, screen, passwords or keystrokes.
