<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F10c: the 2026-11-06 audit and what it fixes

Requested by the maintainer on 2026-11-06: validate the project and its
code so far, then fix what a review finds. Status: M1 through M4 are
done; three small items remain, planned in "Remaining after M1-M4". The
maintainer approved the plan and the Compliance naming on 2026-11-06.

## Method and scope

The automated battery is green: 646 Rust tests, clippy with `-D warnings`,
cargo-deny, no schema drift, 119 UI tests, 81% line coverage, shellcheck
clean. The findings below come from a line-by-line review of the core,
sys, varlink, proto, token and cli crates, plus a targeted pass over the
VPN import parsers, the DNS resolver front end, the MCP door and tokens,
the nfqueue parser, the Tauri capabilities and the packaged units. A
full-depth pass over every plugin and over the DNS and MCP internals is
still open and is milestone M4 of this plan.

No v1.0 tag should happen before M1 and M2 are done and verified.

## P0, fix first

1. The polkit subject is not bound to the connection.
   `crates/ibexwall-core/src/api.rs` (`identity_of`) reads the start time
   from `/proc` on every call instead of at accept, and the subject sent
   to polkit carries no uid, so the decision can be made about a
   different process than the one on the socket. Fix: capture uid, pid
   and start time at accept and pass them together; move to a pidfd
   subject when available.
2. The executor work file is world readable. Ops go to
   `/run/ibexwall/executor/<tx>/ops.json` through `File::create`, the
   runtime directory is 0755 and `ibexwalld.service` is the one daemon
   unit without `UMask=0077`, so a plan containing a VPN profile leaves
   its private key readable by every local user until reboot, while the
   preview deliberately hides it. Fix: 0700 transaction directory, 0600
   file, `UMask=0077`, `StateDirectoryMode=0750`, and remove the
   directory when the run ends.
3. `..` passes the path gate. `path_under_any` is a string prefix test,
   so a plan can name `/etc/sysctl.d/../../../outside.txt`: validate
   accepts it and `remove` executes it, and snapshots read through it
   too. Fix: only absolute, normalized paths; prefix test over
   `Path::components`; the same rule in read, metadata, remove and
   create_dir.
4. One exhausted file table kills the daemon. A failed `accept` ends the
   serve loop and the process exits; there is no connection cap and no
   idle timeout, and the socket accepts any local user. Fix: log and
   back off on accept errors, cap connections, timeout incomplete
   frames; the same for the monitor socket.
5. A failed restore deletes the persisted firewall. When the nft restore
   fails at boot, the persist step sees no chains and removes
   `nft-active.json`; `chains()` and `capture()` treat any nft error as
   empty, so one transient failure silently drops the kill switch and
   the inbound rules on the next boot. The persist helper also uses a
   fixed temp name with no lock or fsync while three callers race. Fix:
   never delete on failure, tell absent from error, unique temp plus
   fsync plus a lock.

## P1, the transaction engine

6. `Rollback` checks neither state nor order: a rolled back or failed
   transaction can be rolled back again, rolling back A over a newer
   committed B destroys B, and a rollback during `applying` runs
   inverses while the apply still executes.
7. Applies are not serialized and plans are replayable: two `Apply`
   calls interleave snapshot and execute, one plan can be applied until
   it expires, and two approvals of one proposal both pass the pending
   check.
8. Rollback lies and gives up: the watchdog publishes `RolledBack`
   whatever the result, crash recovery publishes `RolledBack` over a
   stored `Failed`, `apply` ignores the rollback result, and the inverse
   pass stops at the first error, skipping the rest. A failed state is
   never retried and not undone by uninstall.
9. Snapshots are not durable: blobs and the manifest are plain writes
   with no fsync, while the target files are replaced atomically, so
   power loss can leave a change on disk and an unrestorable snapshot.
10. Plugin calls have no timeout, so a hung `Verify` after a network
    change blocks the confirm watchdog forever; a hung `Check` blocks
    `RunChecks`.
11. `Confirm` races the watchdog: both read `pending_confirm` and act,
    so a confirmed transaction can still be rolled back.
12. `Op::Exec` with piped output deadlocks once the pipe fills, leaving
    the transaction in `applying`.
13. `Reload` runs twice in a rollback, the first time before any file is
    restored, so a first-pass failure aborts the restore.
14. An nft fragment can compile to nothing: an IPv4 source with an IPv6
    destination passes validate and yields no rule, so a blocking rule
    fails open. Refuse at validate when no family matches both lists.
15. Findings collide across plugins: the primary key is the id alone, so
    the plugin that reports an id first drops the other's finding.
16. Nothing is pruned and limits are unbounded: a `limit` of u64::MAX
    becomes unlimited in SQLite, and plans, events, snapshots and
    executor directories grow forever.
17. Reversibility is taken from the manifest, not from the ops, so a
    plan flagged `Irreversible` or `RebootToRevert`, or with a
    non-symmetric `Exec`, passes the proposal gate the MCP text
    promises to refuse.
18. One bad `plugin.toml` or `config.toml` fails `Core::open` before the
    nft restore, and also breaks `--cleanup`, so a broken plugin file
    stops the firewall coming back and blocks uninstall.
19. Audit gaps: the actor is hard-coded instead of the caller identity,
    deleting the newest rows leaves the chain valid because nothing
    anchors the head, the `client` field is caller-declared so quotas
    and audit actors can be spoofed, and `ibexctl proposals show` prints
    no diff, so a person approves file content they never saw.

## P2

20. The org locks are enforced nowhere: `is_locked` has no production
    caller and the plan and proposal paths ignore it.
21. `FileWrite` mode, owner and group are unconstrained at validate, so
    a plugin can write a group-writable setuid-ish file or hand a chosen
    user write access to a unit, and a numeric gid bypasses
    `group_allowed`.
22. Paths under the resolver's owned directory are handled as root: a
    chmod on the answers socket follows a swapped symlink, and the status
    file is an unbounded read that a FIFO can hang.
23. `Subscribe` stalls silently when the broadcast lags: the loop ends,
    no final frame is sent, the connection stays open.
24. `Mask` has no working inverse (`enable` fails on a masked unit).
25. A getsockopt failure yields uid 0 and pid 0 instead of refusing.
26. Snapshot read errors are swallowed into "did not exist", so a
    rollback can delete a file it failed to read.
27. `confirm_timeout_s` is unbounded: negative rolls back at once, huge
    disables the window, and the addition can overflow in debug builds.
28. `Manifest::validate` checks nothing in `[privileges]`: an empty
    `write_paths` root matches everything, `nft_prefix` is not tied to
    the plugin id, and the signature covers `plugin.toml` but not the
    binary.
29. `core.config` is never reloaded, so `PlanStale` cannot fire during a
    daemon's lifetime, and one view helper double-prefixes sandbox paths.
30. Token names ending in a backslash produce invalid TOML, and
    `valid_day` accepts `2026-02-31`.
31. `ibexctl settings --set` rejects any non-JSON value containing `=`.

## What a targeted pass found elsewhere

The WireGuard parser is safe (the `expect("peer")` paths are unreachable:
a `[Peer]` header always pushes the peer first, and script hooks are
refused), the nfqueue parser is bounds-checked and skips malformed
messages, the MCP door verifies Argon2id hashes with a decoy for unknown
ids, the Tauri capabilities are `core:default` only with a closed CSP,
and the DNS unit binds from settings on loopback. Deeper DNS and MCP
review belongs to M4.

## Tests that prove less than they claim

- `FakeFs` has no symlink or `..` semantics, so finding 3 cannot be
  caught by the current suite.
- The symmetric-exec rollback test never calls rollback.
- The slow-subscriber test has no assertion.
- The oversized-frame test accepts any error or timeout.
- The chain test only deletes the first row.

## Repository and docs mismatches

- `fuzz/README.md` describes cargo-fuzz targets and a nightly CI job;
  neither exists (the spec's SEC-08). Add the targets and the job, or
  fix the README to say it is planned.
- `profiles/README.md` says usage profiles are TOML data completed in
  F7, but the directory holds only the README while the profiles live in
  code. Populate or reword.
- `deny.toml` ignores RUSTSEC-2024-0370 (unmaintained, from the GTK
  stack) and cargo-audit also reports RUSTSEC-2024-0429 (glib unsound,
  no known exploit). Track both for removal.
- `ibexwall-exporters` and `ibexwall-web` are placeholders; that is
  expected for F11, and the F11a plan uses the exporters crate.
- STATUS and the release checklist were stale; refreshed in this change.

## Milestones

1. M1, the P0 set. Done on 2026-11-06: five commits with a unit test
   each (paths, executor privacy, nft persistence, accept robustness,
   identity binding), the battery green at 656 tests, and a VM run per
   the phase matrix. Verify: unit tests per fix plus VM scenarios where
   an unprivileged user cannot read the executor file, a traversal plan
   is refused at validate, socket exhaustion leaves the daemon serving,
   and a corrupt persistence file keeps the firewall on reboot.
2. M2, the transaction engine (findings 6 to 19). Landed on 2026-11-06,
   except the parts noted below. Verify: interleaving and double-approval
   tests, a crash injected between steps, a property test that no plan
   without a real inverse passes the gate, and an audit chain whose
   truncated tail is detected.
   Done: a single semaphore serializes every engine mutation, a plan is
   consumed once and a proposal claimed once, Rollback checks state and
   refuses to restore over a newer transaction, every inverse is
   attempted and errors aggregated, snapshots are durable, plugin calls
   have a deadline, the reload runs once, an nft familyless rule is
   refused, findings are keyed by plugin and id, list limits are clamped,
   reversibility comes from the ops and an irreversible plan is refused at
   apply, the firewall is restored before a broken config or plugin file
   can stop the daemon, a failed rollback is retried on boot and included
   in uninstall, a failed apply or verify records the real outcome, the
   audit head is anchored so a deleted tail is detected, plans and events
   are pruned, and a proposal approval shows the diff it reviews.
   Still open from M2: the audit actor is hard-coded as `user` instead
   of the caller identity, and orphaned snapshots are not yet pruned.
3. M3, the P2 set plus the unit and permissions review. Landed on
   2026-11-06: the confirmation window is bounded, a lagged subscriber
   ends cleanly, tokens refuse a backslash name and an impossible date,
   FileWrite modes and ownership are constrained, the organization locks
   are enforced, a snapshot read error fails instead of reading as
   absent, `ibexctl --set` accepts any value, a masked unit is unmasked
   before its enablement is restored, the manifest `write_paths` are
   validated, and the DNS status path no longer double-prefixes under a
   sandbox root. Verify: the full battery plus `--phase f0` to `--phase
   f10` on the five distros.
   Accepted, not fixed: the DNS answers socket chmod and the status file
   read are unreachable to a local user because the runtime directory is
   root-owned 0755. The configuration is now re-read before planning,
   applying and reading config, so a lock or setting change takes effect
   without a restart.
4. M4, the rest of the audit: full-depth pass over every plugin and the
   DNS and MCP internals, `FakeFs` symlink semantics, the weak tests
   above, and the fuzz decision. Verify: findings folded in, battery and
   matrix green. The weak tests now assert, and the fuzz decision is to
   defer the cargo-fuzz targets and nightly job to after v1.0 (they need
   a nightly toolchain); the README says so. The deep pass found and
   fixed two false passes (vuln.cves reading an unrecognized output as
   patched, and net.nts claiming authenticated time with chronyd
   stopped), the MCP server logging a denied VPN profile's key, a
   non-loopback DNS listen, a missed `Defaults !authenticate` in
   system.posture, and a catalog vs sysctl disagreement on ptrace_scope
   and tcp_syncookies. The WireGuard, OpenVPN, blocklist, MCP HTTP, nfq
   and net-common parsers are clean. The core now reports the DNS
   enforcement chain on GetDnsStatus, and FakeFs normalizes `..` and
   refuses a symlinked parent like the real filesystem.

## Remaining after M1-M4

Closed on 2026-11-07. Items 1 and 2 turned out to be already done in
code (the plan notes were stale): the audit actor has carried the
caller's uid since the M1 identity work (`user:<uid>` from
`Identity::actor`), and snapshot pruning runs at every `Core::open`.
Item 3 is now fixed as defense in depth, and pruning also runs after a
rollback:

1. The audit actor names the caller (`user:<uid>`), verified in code;
   the stale note is retired.
2. Snapshots of rolled-back transactions are pruned at daemon start, and
   now also right after a successful rollback, so a long-running daemon
   does not accumulate them.
3. `RealFs::read` opens with `O_NONBLOCK`, refuses anything but a
   regular file by the open handle, and caps the read at 16 MiB: a FIFO
   swapped over the DNS status file fails instead of hanging the
   `GetDnsStatus` call (tested with a real FIFO). The answers socket
   chmod verifies via `symlink_metadata` that the path is still the
   bound socket before and after the change, refusing a swapped
   symlink (tested); the residual bind-to-chmod window needs an
   fd-based fchmod, which the unsafe-free workspace does not have, and
   the directory is root-owned.
4. Fuzz targets and the nightly job are deferred to after v1.0 (they
   need a nightly toolchain); the README already says so. Revisit at
   the v1.1 or F11b planning.

## Clean areas, for the record

Every dispatched method maps to a polkit action before dispatch, the nft
and command paths use typed fragments and fixed argv with no injection,
no lock is held across an await, no secret reaches a log line, and
`write_atomic` itself is sound for symlinks, `..` and fsync.
