<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F2 report: posture, UI and TUI (v0.1 alpha milestone)

Date: 2026-11-02. Plan: `docs/plans/F2-posture-ui.md`.

## What was done

- Plugin SDK and the check results contract (`pass | fail | na` per check,
  plus findings); the core stores results and computes the spec score.
- `system.posture` (14 checks) and `system.ports`, validated against real
  fixtures collected from five distros.
- Svelte 5 UI: Overview, System posture (with "how we calculate"),
  Plugins (list, detail, permissions, simulate/apply/confirm/undo),
  History, Settings (language and theme). Light and dark themes, Fluent
  en and pt-BR, loading/empty/error/denied states.
- Tauri 2 shell (`com.ibexwall.IbexWall`): typed commands over varlink,
  strict CSP, `core:default` only, no updater, tray icon, desktop entry,
  org shield as logo and icon.
- TUI (`ibexctl tui`) and the session agent (notifications, `.desktop`
  inventory scanner).
- ADR-0026 executor: `ibexwall-exec` runs each transaction (apply and
  rollback) in a transient unit limited to that transaction's
  directories; the daemon unit no longer writes `/etc`.

## How it was verified

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo deny check`, `cargo xtask schemas --check`:
  clean.
- `cargo nextest run --workspace`: 152 passed.
- UI: `pnpm check` 0 errors, Vitest 29 passed, Playwright 12 passed
  (axe, 2 themes x 2 locales, keyboard navigation).
- VM, five distros (fedora, ubuntu-24.04, ubuntu-26.04, debian, arch):
  - `--phase f1`: 9/9 scenarios on each, including s8 (a write outside
    the transaction's directories is blocked with the executor active);
  - `--phase f2`: 3/3 on each (plugins enable, findings, posture results
    and manifest as the UI consumes them).
- Visual review against the mockups by the maintainer, in the running
  Tauri app (sandboxed daemon). Defects found and fixed: plugin switch
  drawn as a circle, History stuck on loading, empty Settings, 1970
  detection time, sandbox daemon blocked by the host polkit.

## Deviations

- ADR-0027: `ibexwall-varlink` is Apache-2.0 OR MIT (permissive crate).
- RUSTSEC-2024-0370 (unmaintained `proc-macro-error`, from the GTK stack
  under Tauri) is ignored in `deny.toml` with a note.
- Under `IBEXWALL_ROOT` the daemon authorizes every action for its own uid
  only (the host polkit has no IbexWall policy). Production is unchanged.
- pt-BR: "Postura do sistema" renamed "Segurança do sistema".

## Risks

- The mockups' Overview panels (recommendation, recent activity) and the
  Plugins profile selector, card grid and side detail are not built; the
  nav entries for Apps, Firewall, DNS and AI Assistant arrive with F3 to F8.
- The org avatar is 460 px; the 1024 px icon is upscaled. A vector source
  would improve large sizes.
- Tray icon on GNOME needs the AppIndicator extension.
- Updates and firmware checks are "not assessed" until F7.
- The Tauri app has been run only against the sandboxed daemon, on Fedora.
  Omarchy and EndeavourOS manual runs are pending (maintainer).

## Pending

- Maintainer: acceptance of F2; manual runs on Omarchy and EndeavourOS.
- Decide whether the missing mockup panels block v0.1 or move to F3.

## Next step

F3 (secure DNS): plan in `docs/plans/F3-secure-dns.md`.
