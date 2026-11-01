<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# spec/ — generated contracts

Everything under `schemas/` and `idl/` is **generated**; do not edit by
hand.

- Source of truth: Rust types in `crates/ibexwall-proto`.
- Regenerate: `cargo xtask schemas`
- Verify (CI): `cargo xtask schemas --check` fails when committed files
  differ from generated output, including stale leftovers.
- Serialization is canonical and deterministic (sorted keys, stable
  field order), so re-running the generator on unchanged code produces
  byte-identical files.

Layout:

- `schemas/<Type>.schema.json` — JSON Schema (draft 2020-12) per
  contract type, including the full `Op` tagged-union detail.
- `idl/com.ibexwall.{Core,Plugin,Policy}.varlink` — varlink IDL for the
  three interfaces. Type blocks are converted from the schemas; method
  and error declarations are templates in `xtask/src/idl.rs` (they have
  no schema representation). `Op` and free-form payloads travel as
  `object` here, with the precise shape in the JSON Schemas.
- `examples/` — human-readable reference samples (manifest and plan)
  kept in sync manually; validation happens through the schemas.

TypeScript types for the UI will be generated from these schemas
(starting F2).
