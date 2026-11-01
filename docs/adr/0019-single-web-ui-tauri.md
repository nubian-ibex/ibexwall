<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0019: Single web UI in a Tauri shell (D-019)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0005

## Context

One interface must run natively on GNOME, KDE Plasma and Hyprland
(Wayland and X11), serve a remote web gateway, keep accessibility (WCAG
2.2 AA) and i18n (Fluent), and avoid maintaining two frontends. Classic
options would force a toolkit choice (GTK vs Qt) that splits the
community.

## Options considered

- **GTK4 (Adwaita)**: native on GNOME; foreign on KDE/Hyprland.
- **Qt (QML)**: strong cross-DE; not native on GNOME; team/skill split
  with the Rust backend.
- **Electron**: heavy runtime on a security product; poor optics and
  resource goals (idle RAM budget).
- **Svelte 5 + TS in Tauri 2** (chosen): one UI for the desktop shell
  and the optional web gateway, Rust side stays a thin varlink client,
  small footprint, strict CSP, no remote content, updates via the
  distro.

## Decision

The UI is a single Svelte 5 + TypeScript app. The desktop ships as
Tauri 2 (app id `com.ibexwall.IbexWall`) with minimal capabilities and
strict CSP; `ibexwall-web` can serve the same UI remotely (off by
default). TypeScript types are generated from the JSON Schemas in
`spec/`. TUI is a separate ratatui frontend for terminals.

## Consequences

- WebViews vary per-WebKitGTK version; e2e and visual review must cover
  the matrix over time.
- Accessibility depends on webview a11y bridges; must be tested (axe +
  keyboard walkthroughs), not assumed.
- Design tokens, i18n and components are defined once in the spec and
  reused by both delivery modes.
