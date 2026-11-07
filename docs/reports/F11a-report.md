<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F11a report: Compliance

Date: 2026-11-06. Plan: `docs/archive/plans/F11a-compliance.md`.

## What was done

The Compliance section, the local half of F11: one question per framework,
which of its technical controls does this machine meet right now, which does
it not, and which can software not decide.

- A pure evaluator in the core turns the stored check results, the profile,
  the attestations and the exceptions into one of six control states:
  compliant, non-compliant, not-assessed, needs-attestation, not-applicable
  and excepted. Unknown is never a pass: a missing, stale or unknown check
  makes its control not-assessed, and an expired exception falls back to the
  real state.
- The `ibexwall-profiles` repository, public, with a JSON Schema, a registry
  of the check ids the product emits, and the six first-release profiles:
  IbexWall Baseline, LGPD (art. 46), CMN 4.893/2021 as amended by 5.274/2025,
  NIST SP 800-53 Rev. 5, NIST SP 800-171 Rev. 3 and ISO/IEC 27001:2022 Annex A
  theme 8. CIS Benchmarks stay unmapped until the licensing review.
- Nine new checks, each read-only and honest about "not assessed", for
  password age, inactive accounts, sensitive-file permissions, sudo logging,
  the login banner, the audit daemon and journald retention, time
  synchronization, package signatures and default-deny inbound.
- Attestations and exceptions recorded with an owner and an expiry, authorized
  by polkit and written to the audit chain.
- The shipped profiles are packaged into `/usr/lib/ibexwall/profiles`; an
  operator's files in `/etc/ibexwall/profiles` shadow them by name.
- Surfaces: `ListComplianceProfiles`, `GetCompliance` and `ExportCompliance`
  on the daemon; `ibexctl compliance list|show|export`; two read-only MCP
  tools under a read scope; and the Compliance screen in the UI, all in five
  languages.
- The export signs the report, the attestations, the exceptions and the
  audit-chain head with a device ed25519 key (generated once, stored 0600),
  and offers JSON, CSV and OSCAL. A tampered export fails verification.
- `cargo xtask vm-test --phase f11a` stages, packages and installs the tree,
  proves the six profiles are listed, evaluates the baseline with honest
  states, and flips `sysctl.hardening` from fail to pass through the
  recommended preset.
- The website gained a Compliance section (one page per framework, five
  languages, each with its honest limits and the "not a certification" note),
  and the documentation gained a Compliance guide.

## How it was verified

- 701 workspace tests, clippy, fmt, cargo-deny and schemas (49 files) clean.
- `cargo xtask vm-test --phase f11a` green on fedora, ubuntu-24.04,
  ubuntu-26.04, debian and arch: the packages build, install, the six
  profiles are listed, the baseline reports 26 controls with a mix of honest
  states (two needs-attestation), and the sysctl check flips fail to pass.
- The signed-envelope round trip and tamper rejection are unit-tested; every
  shipped profile parses and carries its checks.

## Defects found and fixed along the way

- The sysctl plan proposed a write for every recommended key whose live value
  differed, including keys the kernel cannot read (`net.core.bpf_jit_harden`
  once the BPF JIT is locked down). The engine then refused to snapshot the
  key, so applying the recommended preset failed outright on a fresh machine.
  The plan now skips keys it cannot read, matching how the check already
  ignores them.
- The first version of the phase's profile-list check piped into
  `python3 -` alongside a heredoc, which made the heredoc swallow the pipe;
  it now writes to a file first.

## Deviations and open points

- The OSCAL output is a best-effort assessment-results structure; validating
  it against the official NIST schema is a follow-up.
- Profile signature verification is a release concern, not done yet: the
  shipped profiles are a snapshot of `ibexwall-profiles`, and a future profile
  release will be signed and need no app release.
- CIS, PCI DSS and SOC 2 follow as profile releases after their licensing
  review. DISA STIG and ANSSI-BP-028 stay reached through OpenSCAP, not mapped
  by IbexWall.
- F11b, the managed-mode contracts (locks, signed bundle, report), is
  unaffected and remains open.
