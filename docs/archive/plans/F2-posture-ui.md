# F2 — Posture, UI and TUI (v0.1 alpha)

Goal: first user-visible release. Read-only posture plugins, a score the
user can understand, a Svelte web UI inside a Tauri shell, a TUI, and a
minimal session agent. Plus the ADR-0026 executor, because it must land
before v0.1.

Status: in progress (autonomous mode, decided 2026-11-01).

## Preconditions and blockers

- [x] F1 accepted; ADR-0026 accepted (option 2)
- [ ] Host packages for Tauri 2 builds (needs sudo, user action, needed at
      M6 only): `sudo dnf install webkit2gtk4.1-devel libsoup3-devel librsvg2-devel`
- Node 22 and pnpm 10 are present.

## Scope decisions

- **Check results contract (additive, `com.ibexwall.Core` v1).** The spec
  score is `sum(weights of passed) / sum(weights applicable) * 100`, which
  needs passes and not-applicable results, not only findings. Plugin
  `Check` returns `results` (`pass | fail | na` per check id, with
  severity) next to `findings`; the core stores them and computes the
  score. F1's rough score is replaced.
- **Check plugins read files, they do not run commands.** Secure Boot,
  lockdown, LUKS/TPM2, swap, SELinux/AppArmor, active firewall, mounts,
  core dumps and sudo NOPASSWD come from `/sys`, `/proc` and `/etc`, so the
  plugin keeps an empty exec allowlist and no capabilities. Items that need
  PackageKit or fwupd (pending updates, automatic updates, HSI) belong to
  `system.updates` and `system.firmware` in F7; posture shows them as
  "not assessed yet", never as passing.
- **UI transport.** The UI talks to a `Transport` interface: Tauri commands
  (Rust varlink client) in the app, and a fixture transport for Vitest and
  Playwright (core simulated, as the spec's testing section asks). The
  `ibexwall-web` HTTP gateway is not part of F2.
- **Agent.** F2 delivers notifications for new high-severity findings and
  the `.desktop` inventory scanner with tests; sending the inventory to the
  core arrives with `net.apps` in F4.
- **No release tag or push of a release** without your explicit request;
  "v0.1 alpha" is the milestone name.

## Milestones (each lands green: fmt, clippy, nextest, deny, no drift)

### M1 — Contract, SDK and score
- Proto: `CheckResult`, `CheckOutcome`; `Plugin.Check` reply gains
  `results`; schemas and IDL regenerated; TypeScript generation step
  (`cargo xtask schemas` also emits `ui/src/gen/`).
- `ibexwall-sdk`: a small server helper (`Plugin` trait with `describe`,
  `check`, `plan`, `verify`; stale-socket handling; tests) so posture
  plugins and `dev.echo` stop hand-rolling the protocol.
- Core: store results, real score and per-plugin protection state;
  `GetPosture` returns them; `RunChecks` persists results.

### M2 — `system.ports`
- Parse `/proc/net/{tcp,tcp6,udp,udp6}`; flag listeners on `0.0.0.0` and
  `::`; resolve process names only when readable. Fixture tests, proptest
  on the parser.

### M3 — `system.posture`
- Checks: Secure Boot, kernel lockdown, LUKS (crypttab, `/sys/block`
  dm-crypt), TPM2 device, encrypted swap, SELinux/AppArmor, active
  firewall (firewalld/ufw/nft unit state via `/etc` and `/run`), `/tmp` and
  `/dev/shm` mount options, core dumps, `sudo` NOPASSWD, plus "not
  assessed" markers. Own wording and own check ids; framework IDs only as
  references (verified before use).
- `cargo xtask fixtures collect --distro <id>`: copies the relevant files
  from the VM into `tests/fixtures/<distro>/`. Acceptance runs the plugin
  against real fixtures from Fedora, Ubuntu, Debian and Arch.

### M4 — UI foundation and Overview
- `ui/`: Svelte 5, Vite, TypeScript strict, pnpm, ESLint, Prettier.
- Design tokens (light and dark), IBM Plex via `@fontsource` (OFL, bundled),
  Lucide icons, base components (AppShell, ScoreRing, ProtectionCard,
  StatusBadge, Switch, SegmentedControl, EmptyState, Toast, Dialog).
- Fluent i18n: `en` source and `pt-BR`; named arguments only.
- Overview screen from mockup 01, with loading, empty and error states.

### M5 — Plugins, Posture detail and History
- Plugins list and detail (permissions in plain words plus technical
  line, config form generated from JSON Schema, findings with references,
  Simulate, Apply, Rollback), DiffViewer, MayAffectCallout,
  RestorePointNote, ConfirmCountdown (`aria-live`), LockBadge.
- Posture detail with "How we calculate" showing the formula and weights.
- History and restore points.
- States: empty, loading, error, polkit denied, incompatible plugin,
  degraded.

### M6 — Tauri shell, a11y, e2e
- Tauri 2 app (`com.ibexwall.IbexWall`): strict CSP, no remote content,
  minimal capabilities, no updater; Rust side is a varlink client with
  typed commands.
- Vitest units, Playwright e2e on the fixture transport, axe with no
  serious violations, full keyboard navigation, reduced motion, dark
  theme contrast checked with a tool.
- Visual review against the mockups is yours (screenshots attached to the
  phase report).

### M7 — TUI
- `ibexctl tui` with ratatui: overview, plugins, history. Live refresh from
  `Subscribe`.

### M8 — Session agent (minimal)
- `ibexwall-agent` user service: subscribes to events and sends desktop
  notifications for new high or critical findings; `.desktop` inventory
  scanner with tests. User unit in `packaging/`.

### M9 — ADR-0026 executor
- `ibexwall-exec` helper started through `StartTransientUnit` with
  `ReadWritePaths=` limited to the directories of one transaction; the
  daemon unit drops `/etc` from its own `ReadWritePaths`. Fake in
  `ibexwall-sys` for engine tests; VM scenario proving a plan cannot write
  outside its declared directories.

### M10 — VM acceptance, docs, closeout
- VM suite `--phase f2`: posture and ports on the five distros, UI built
  and served to Playwright against a real daemon on one distro.
- Update threat model (new surface: UI CSP, Tauri commands, agent),
  capabilities matrix, user docs, STATUS, phase report.

## Acceptance criteria (spec section 15 F2, plus ours)

- [ ] Posture is correct on Fedora, Ubuntu, Debian and Arch against real
      fixtures
- [ ] UI matches the mockups (visual review by the maintainer)
- [ ] axe reports no serious violations; keyboard navigation is complete
- [ ] Dark and light themes; `en` and `pt-BR` complete
- [ ] Score formula visible in the UI and covered by unit tests
- [ ] ADR-0026 executor: out-of-directory write attempt is blocked in a VM
- [ ] Coverage targets unchanged (core 80%, engine 90%)

## Risks

- Tauri and WebKitGTK differ per distro; the UI must not depend on newer
  web APIs than the oldest WebKitGTK we target.
- Check wording can sound alarmist; copy review against the tone rules in
  the spec (calm, consequence first).
- Phase size: UI plus TUI plus agent plus executor. Milestones are
  independent; M6 and M9 may slip past "v0.1" if blocked, and that will be
  reported, not hidden.
- Mockup source files are `.dc.html`; the PNG mockups are the visual
  reference and I cannot judge pixel fidelity myself.
