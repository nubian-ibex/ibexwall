<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0020: i18n with Fluent, en source, pt-BR mandatory (D-020)

- Status: Accepted
- Date: 2026-11-01

## Context

Findings, events and UI copy are assembled from structured data;
classic gettext-style concatenation breaks plurals/gender and produces
untranslatable strings.

## Decision

Fluent (`.ftl`) in Rust (`fluent-bundle`) and frontend
(`@fluent/bundle`). `en` is the source locale; `pt-BR` ships in the
same commit as any new string; `de`, `fr`, `es` via Weblate later.
Stable message keys; never concatenate translations.

## Consequences

- Message keys are part of the contract surface (e.g. `title_key`,
  `may_affect_keys`); changing them is a compatibility event.
