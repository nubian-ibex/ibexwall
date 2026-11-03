<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0031: the connect monitor uses cgroup/connect hooks on aya

Status: accepted (spike S4-a proven on all five distros, 2026-11-03).
Phase: F4.

## Context

F4 needs per-program connection attribution in monitor mode. The choices
were the `cgroup/connect4`/`connect6` hooks, `sys_enter_connect`
tracepoints, or LSM hooks.

## Decision

cgroup/connect4 and connect6 on aya 0.16 / aya-ebpf 0.3, one program per
family, always returning 1 (allow; see the correction below), submitting a fixed 52-byte
little-endian record to one ring buffer; the loader polls the map fd so
events are drained as they happen.

## Findings (all five distros, 2026-11-03)

- Loads and attaches on every kernel in the matrix (Fedora 6.19, Arch
  current, Debian 13, Ubuntu 24.04 and 26.04) under root; cgroup v2 root
  attach, `CgroupAttachMode::Single`.
- The verifier rejects reading a field the attach type does not own:
  connect6 may not read `user_ip4`, connect4 may not read `user_ip6`.
  With the family as a constant, the other branch compiles away.
- `user_ip4`/`user_ip6` hold the sockaddr's own bytes in memory: on the
  little-endian BPF target, `to_ne_bytes` reproduces them (byte-swap bugs
  hide behind symmetric addresses like 9.9.9.9, so the VM probe uses
  asymmetric ones). `user_port` carries the 16-bit port in network order
  in its low half.
- Short-lived processes can exit before userspace resolves `/proc`: the
  loader wakes on the map fd, which covers processes that live a few
  milliseconds, but `curl`-fast processes need kernel-side identity. M1
  records kind, id, exe path and hash via CO-RE task reads; until then
  the event carries pid, comm and cgroup id, and exe resolution is best
  effort.
- Overhead bounds measured in VM (asserted in the scenario): under 3 us
  of connecting-process CPU per connect in the hook, under 20 us of
  loader CPU per event.

## Consequences

- Monitor only: nothing is dropped, so a full ring buffer loses events
  (counted) rather than affecting traffic.
- The eBPF crate is outside the workspace (`cargo xtask ebpf` builds it
  with nightly, `rust-src` and `bpf-linker`), so ordinary workspace
  builds and CI need no BPF toolchain; the loader looks the ELF up at
  runtime (env `IBEXWALL_EBPF`, `/usr/lib/ibexwall/ebpf`, `target/bpf`).
- `bpf-linker` is the upstream prebuilt binary in `~/.local/bin`; the
  cargo build needs llvm-config, which is not installed on this host.

## Correction (2026-11-03): the hooks must return 1

For `cgroup/connect4` and `connect6`, a program that returns 0 makes the
`connect()` fail with EPERM; 1 lets it proceed. The first version of the
spike returned 0 and so silently blocked every outbound connection while
loaded. The spike scenarios did not notice because they ignored
`OSError`; the end-to-end run did, when DNS stopped working in the VM.
The programs now return 1 on every path (including a failed recording),
and scenario e0 requires real IPv4 and IPv6 loopback connections to
complete with the monitor attached.
