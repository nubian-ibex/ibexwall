<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F11a: Compliance, the machine against a named framework

Requested by the maintainer on 2026-11-06. Status: approved; M1 through
M8 are done. The maintainer approved the plan and the Compliance naming on
2026-11-06.

A new Compliance section answers one question per framework: which of its
technical controls does this machine meet right now, which does it not, and
which can software not decide. It splits F11: this part is local and has no
dependency on the managed-mode contracts, which stay in F11b.

## What this is not

IbexWall does not certify anything, and the product never says "certified".
Certification comes from an independent audit, which also covers processes,
people and scope that no local agent can see. The words in the UI and the
site are "compliant with the mapped technical controls", always with the
framework version and the date. Every result screen and export carries that
limit.

## Rules that do not change

- Read-only. Assessing runs no new system effect. A failed control links to the
  plan of the plugin that owns it, and that plan goes through the normal flow:
  review, snapshot, approval, rollback.
- Unknown is never a pass. A check that did not run, could not read its input or
  is older than the freshness limit makes its control "not assessed".
- No telemetry. A report leaves the machine only when the person exports it.
- Licensed texts are not copied. Each control has our own title, the reference
  number, a URL and the date it was consulted.

## Control states

- `compliant`: every required check passed and is fresh.
- `non_compliant`: at least one required check failed.
- `not_assessed`: a required check is missing, stale or unknown.
- `needs_attestation`: the control is organizational, so software cannot
  decide it. A person records a statement, an owner and an expiry date.
- `not_applicable`: every required check says so, or an exception applies.
- `excepted`: a risk accepted by a named owner with an expiry date. Shown apart,
  never counted as compliant. An expired exception falls back to the real state.

A framework shows counts of each state, never one percentage that hides the
not assessed and attestation groups.

## Frameworks

Versions checked against the sources on 2026-11-06. The specification lists
older versions in two cases, marked below.

First release, mapped natively:

- IbexWall Baseline, our own profile. No license question, and the default.
- Lei 13.709/2018 (LGPD), art. 46, with art. 6 VII and art. 49. The law names
  no technical control, and ANPD may set minimum standards (art. 46 par. 1).
  The mapping is therefore our reading, and the screen says so.
- Resolução CMN 4.893/2021 as amended by Resolução CMN 5.274/2025, art. 3 par. 2.
  The specification predates the amendment, which raised the list to 14 items.
  An endpoint can give evidence for: I authentication, II encryption, III
  intrusion prevention and detection (host part), V malware protection, VI
  traceability (host part), VIII vulnerabilities, IX access control, X secure
  configuration profiles, XI network protection. Attestation only: IV leak
  prevention, VII backups, XII certificates, XIII interfaces, XIV threat
  intelligence.
- NIST SP 800-53 Rev. 5 (release 5.2.0) and SP 800-171 Rev. 3, the host subset.
  Public, and NIST publishes the catalogs in OSCAL.
- ISO/IEC 27001:2022 Annex A, the theme 8 controls a host can show (number and
  title only).

Second release, after the first has been reviewed:

- PCI DSS v4.0.1. The specification says 4.0, retired on 2024-12-31. Host
  subset only, and a warning that scope is the cardholder data environment.
- SOC 2 Common Criteria CC6 and CC7. These are criteria, not controls, so
  this is evidence for an auditor and never a verdict.

Through OpenSCAP, not mapped by us: DISA STIG, ANSSI-BP-028, and whatever else
the distribution's SCAP Security Guide content offers. `system.openscap`
already runs those; the screen lists the profiles the content really has.
That differs per distribution and Arch has no packaged content, so nothing is
promised per distro.

CIS Benchmarks: no native profile and no claim. The CIS certification page
states that a product that incorporates a Benchmark needs CIS certification
before any sale, distribution or marketing. Running the distribution's content
through OpenSCAP stays possible as the person's own choice. Revisit after the
legal review, or if the project joins the CIS vendor program.

Later: NIS2, DORA, BSI IT-Grundschutz.

## What the current checks already prove

- Encryption at rest: `posture.disk_encryption`, `posture.swap_encryption`,
  `posture.tpm2`.
- Secure boot chain: `posture.secure_boot`, `posture.lockdown`,
  `posture.firmware_hsi`, `firmware.*`.
- Host network protection: `posture.firewall`, `ports.exposed_services`,
  `exposure.*`, `wifi.open_networks`, `dns.plain_upstream`, the `vpn.*` checks.
- Secure configuration: the 26 items of the hardening catalog, `sysctl.*`,
  `posture.mac`, `mounts.*`, `posture.core_dumps`, `coredump.*`, `ssh.*`.
- Access control: `accounts.empty_passwords`, `accounts.uid0`,
  `accounts.lockout`, `posture.sudo_nopasswd`, `session_lock.automatic`,
  `usb.*`.
- Vulnerabilities and patches: `posture.updates_pending`,
  `posture.updates_automatic`, `updates.automatic`, `cves.security_updates`.
- Malware and integrity: `av.*`, `integrity.*`, `rootkit.*`, `persistence.*`.
- Time: `nts.authenticated_time`.
- Change traceability: the core's hash-chained audit log.

## Checks to add

Almost every framework asks for these, and nothing measures them today:

- Audit daemon active and its rules loaded (`auditd`).
- Log persistence and retention (journald storage, size and age limits).
- Password policy (`pwquality`, `login.defs`, maximum age).
- Inactive and expired accounts.
- Permissions of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` and sudo logging.
- Package signature verification enforced by the package manager.
- Time synchronized at all, separate from authenticated time.
- Default-deny inbound on both IPv4 and IPv6, beyond "a firewall is running".
- Login banner, only where a framework requires one.

## Design

- Data: profiles are YAML in a new `ibexwall-profiles` repository, with schema
  and CI (links resolve, every reference has a URL and a date, every check id
  exists). Fields: `framework`, `version`, `control_id`, `title` (ours),
  `kind` (`automated` or `attestation`), `checks`, `references`. A profile
  release is signed and needs no app release; the core refuses a bad signature.
- Evaluation: in the core, a pure function of the stored `check_results` (they
  already carry `pass`, `fail`, `not_applicable`, `not_assessed` and
  `checked_at`), the profile and the attestations. No new plugin.
- Contract: `ListComplianceProfiles`, `GetCompliance(profile)`,
  `SetAttestation` and `SetException` (polkit, audited),
  `ExportCompliance(profile, format)`. `BuildReport` is declared in the IDL and
  not implemented yet; it shares this evidence and lands in F11b.
- Evidence: a signed report per device with the date, the profile version, each
  control's state, the raw check results, the attestations and the head of the
  audit chain. Formats: JSON, CSV and OSCAL Assessment Results (`ibexwall-exporters`,
  a placeholder today, or a new module). PDF after that. No browsing data, files
  or personal content; the report schema already forbids them.
- Surfaces: a Compliance screen after Hardening, `ibexctl compliance`, and two
  read-only MCP tools. Strings in all five languages.

## Milestones

M0 is a hard prerequisite: a false pass in a probe becomes a false compliance
statement, so the probe fixes in `docs/plans/F10c-audit-fixes.md` land first.

1. M1 Contract and evaluator: types, schemas, the pure function, state storage.
   Done on 2026-11-06: the compliance types (with JSON schemas), the pure
   `evaluate` over the stored checks, attestations and exceptions, the
   attestation/exception tables, and table plus property tests.
   Verify: table tests for each state, including stale and unknown checks, and a
   property test that no combination with an unknown required check yields
   `compliant`.
2. M2 `ibexwall-profiles`: schema, CI, IbexWall Baseline and the verified
   mappings of the first release. Done on 2026-11-06: the repository is
   public at github.com/nubian-ibex/ibexwall-profiles with a JSON Schema, a
   registry of the check ids the product emits, six profiles (Baseline,
   LGPD, CMN 4.893/5.274, NIST 800-53 r5, NIST 800-171 r3, ISO 27001:2022
   theme 8) and a CI that refuses a reference without an https URL or a
   recent date, or a check id that does not exist. Verify: CI refuses a
   reference with no URL or date and a check id that does not exist.
3. M3 The new checks. Done on 2026-11-06: system.accounts (password age,
   inactive accounts, sensitive-file permissions, sudo logging, login
   banner), system.audit (the audit daemon and journald retention),
   net.nts (time synchronized at all), system.updates (package
   signatures) and net.firewall (default-deny inbound), each read-only,
   honest about "not assessed", in five languages, and registered in the
   profiles repository. Verify: unit tests with sandbox fixtures, VM
   scenarios on five distros with the setting on and off.
4. M4 Attestations and exceptions: owner, expiry, audit. Done on
   2026-11-06: SetAttestation and SetException record a statement or an
   accepted risk with an owner and an expiry, authorized by polkit and
   written to the audit chain; the evaluator treats an expired exception
   as falling through to the real state. Verify: an expired one reverts to
   the real state; each change appears in the audit chain.
5. M5 CLI, UI and MCP. Done on 2026-11-06: the core loads profiles and
   exposes ListComplianceProfiles, GetCompliance and ExportCompliance,
   `ibexctl compliance list|show` covers the command line, the MCP server
   has two read-only tools under a read:compliance scope, and the
   Compliance screen shows a profile's controls and their states with the
   honest limits, in five languages. Verify: the screen shows exactly what
   the export holds; the MCP tools cannot write; five locales pass
   check-locales.
6. M6 Signed export and OSCAL. Done on 2026-11-06: ExportCompliance signs
   the report, the attestations, the exceptions and the audit-chain head
   with a device ed25519 key (generated once, stored 0600), offers csv and
   oscal formats, and a tampered export fails verification (tested).
   `ibexctl compliance export` exposes all three. Verify: a tampered report
   fails verification; the OSCAL output validates against the official NIST
   schema (the NIST schema check remains a follow-up).
7. M7 `--phase f11a` on five distros. Done on 2026-11-06: a new phase
   stages, packages and installs the tree, proves the six shipped profiles
   are listed, evaluates the baseline with honest states, and flips
   `sysctl.hardening` from fail to pass through the recommended preset. It
   passes on Fedora 45, Ubuntu 24.04, Ubuntu 26.04, Debian 13 and Arch. The
   run surfaced a real bug, now fixed: the sysctl plan proposed a write for
   keys the kernel cannot read (`bpf_jit_harden`), so the engine refused to
   snapshot them; the plan now skips those keys, as the check already did.
8. M8 Docs and site. Done on 2026-11-06: the website has a Compliance
   section with one page per framework in five languages, each with the
   honest limits and the "not a certification" note, and the documentation
   has a Compliance guide. Verify: the site builds and every framework page
   states its limits; the docs build.

## Risks

- Overclaiming. A wrong "compliant" costs a user an audit and the project its
  reputation: every mapping is reviewed, and the wording rule above is tested.
- Interpretation. LGPD and SOC 2 mappings are readings, not official. Legal
  review before public claims.
- Licensing. ISO, AICPA, PCI and CIS texts are protected; references only. PCI
  and CIS names on the site go through the same review.
- Upkeep. Standards change, as the CMN amendment and PCI v4.0.1 show. Profiles
  carry the consultation date and CI flags any older than 12 months.

## Decisions needed from the maintainer

1. Name in the UI: "Compliance" (recommended) rather than "Certification".
2. Order: F11a before F11b, as a v1.1 feature (recommended), or inside v1.0.
3. First-release frameworks: the list above (recommended) or a shorter one.
4. CIS: no native profile until the legal review (recommended).

## Sources, consulted 2026-11-06

- LGPD: https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm
- Resolução CMN 5.274:
  https://www.bcb.gov.br/estabilidadefinanceira/exibenormativo?tipo=Resolu%C3%A7%C3%A3o%20CMN&numero=5274
- PCI DSS v4.0.1: https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1
- NIST SP 800-53 5.2.0:
  https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls
- NIST SP 800-171 Rev. 3: https://csrc.nist.gov/pubs/sp/800/171/r3/final
- OSCAL Assessment Results:
  https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
- CIS certification:
  https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/cis-benchmark-configuration-certification
- SCAP Security Guide profiles:
  https://complianceascode.github.io/content-pages/guides/index.html
