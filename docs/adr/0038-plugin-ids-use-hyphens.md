<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0038: Plugin ids use hyphens

Status: accepted (maintainer decision, 2026-11-03). Resolves the naming
inconsistency reported with the F6 report. Phase: F7.

## Context

The manifest rule for plugin ids is `<category>.<name>` with each segment
in `[a-z0-9-]`, but three catalog entries in the spec use underscores:
`apps.flatpak_perms`, `system.session_lock`, `privacy.camera_mic`.

## Decision

The manifest rule wins: segments are `[a-z0-9-]`, so the three become
`apps.flatpak-perms`, `system.session-lock`, `privacy.camera-mic`, and the
spec's catalog table is updated to match. No shipped plugin used the
underscored forms (the F4 Flatpak block plugin is `apps.flatpak-network`).

## Consequences

- One naming rule, already enforced by manifest validation.
- Files and locale keys follow the id (`plugin-<name>-summary`).
