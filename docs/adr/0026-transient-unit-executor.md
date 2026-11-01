<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0026: Transient-unit executor (spike S1-c)

- Status: Proposed (needs a maintainer decision)
- Date: 2026-11-01
- Related: ADR-0007, ADR-0010, docs/threat-model.md

## Context

The core unit grants `ReadWritePaths=/etc /var/lib/ibexwall /run/ibexwall`
because the in-process executor may write any path a manifest declares.
The spec asks whether the executor can instead run in a transient unit
(`StartTransientUnit`) whose `ReadWritePaths=` equals exactly the paths of
one transaction.

## Spike results (Fedora 44, systemd, 2026-11-01, `systemd-run -p ...`)

- `ProtectSystem=strict` plus `ReadWritePaths=<parent dir>`: the atomic
  write (tmp file + rename) succeeds in that directory, while writes to
  other paths in `/etc` and to `/usr` fail with EROFS.
- `ReadWritePaths=<file>` only: rename fails (EROFS on the temporary
  file); only in-place writes work. In-place writes are not atomic, so
  the executor must expose the parent directory, not the file.
- `sysctl.set` works with `ProtectKernelTunables=no` together with
  `RestrictSUIDSGID=yes`.
- Starting a transient unit and waiting for it took about 26 ms.
- Not measured: behavior for a path that does not exist. The
  systemd.exec(5) man page says unit start fails unless the path is
  prefixed with `-`; the daemon would need to create missing drop-in
  parent directories first or use the `-` prefix.

## Options

1. **Keep the in-process executor** (today). Simple. The daemon can write
   anywhere under `/etc`, so a path-validation bug has a large blast
   radius.
2. **Executor helper in a transient unit per transaction** (`ibexwall-exec`
   reads the validated ops, runs with `ReadWritePaths=` set to the
   parent directories of that transaction, minimal capabilities). The
   daemon unit then shrinks to `/var/lib/ibexwall` and `/run/ibexwall`.
3. **Static per-plugin sandbox** (declare `ReadWritePaths` from manifests
   in a drop-in). Coarser than option 2 and fixed at install time.

## Recommendation

Adopt option 2, implemented before v0.1: it is viable and cheap in
latency. Be clear about what it buys: it contains bugs in path
validation and plugin-proposed operations. It does not protect against a
fully compromised daemon, which can still ask systemd to start any
transient unit. The cost is a new helper binary, an IPC for the ops, and
unit-start error handling inside the transaction (a failed start must
roll back like any failed step).

Until accepted, the in-process executor stays and the threat model lists
the wide `ReadWritePaths` as an accepted risk.

## Consequences if adopted

- New crate/binary `ibexwall-exec` and a `Systemd` trait method with a
  fake for engine tests.
- Per-op-type property sets (files, sysctl, nft needing `CAP_NET_ADMIN`
  and `AF_NETLINK`, `systemctl` actions through D-Bus).
- The VM suite gains a scenario that proves a plan cannot write outside
  its declared directories.
