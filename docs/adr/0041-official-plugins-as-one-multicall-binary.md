<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0041: Official plugins ship as one multicall binary

Status: proposed (2026-11-04); the maintainer decides. Phase: F10.

## Context

Today each plugin is its own binary (`ibexwall-plugin-<name>`): 31 binaries,
about 58 MiB unstripped, each one carrying its own copy of the tokio runtime
and the SDK. The plugin contract requires a separate process with its own
sandbox, and the manifest names one binary. Packages should be small.

## Options

1. One binary per plugin, as now. Simplest contract; the largest package.
2. One multicall binary for the official plugins (`ibexwall-plugins`),
   started under the plugin's own name through a symlink or hard link
   (`ibexwall-plugin-vpn` -> `ibexwall-plugins`) and dispatching on argv[0],
   like busybox. The manifest still names `ibexwall-plugin-<name>`, and the
   supervisor still starts one process per plugin, each in its own unit and
   sandbox. Third-party plugins keep shipping their own binary.
3. One long-running process hosting all plugins as threads or tasks. Smallest
   and fastest, and it breaks the isolation the contract promises.

## Decision (recommended)

Option 2. The security boundary is the process and its unit, not the file
on disk; a multicall binary gives up neither. What it gives up is the ability
to update one official plugin alone, which is acceptable for plugins that
release with the core. The size estimate (to be measured in F10) is 6 to 10
MiB instead of 58 MiB, and one artifact to sign instead of 31.

## Consequences

- The SDK grows a `multicall!` entry point that selects the plugin by
  argv[0]; the plugin crates become libraries that export `run()`.
- Packaging creates the links; the supervisor and manifests do not change.
- A bug in shared code affects every official plugin, which is already true
  of the SDK today.
- Third-party plugins are unaffected.
