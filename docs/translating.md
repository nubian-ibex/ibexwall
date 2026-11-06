<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Translating IbexWall

English is the source language and the fallback. The app ships English,
Portuguese (Brazil), Spanish, French and German, and starts in the language
the system asks for (`LANG`, or the first language of the session that is
shipped), unless the person picks one in Settings.

## Adding a language

A language is a set of files, and one line in a list. There is no code to
change in the app.

1. Pick the tag (`it`, `ja`, `pt-PT`). Add it to `LOCALES` in
   `crates/ibexwall-proto/src/names.rs`.
2. Copy `ui/locales/en/ui.ftl` to `ui/locales/<tag>/ui.ftl` and translate it.
3. For every plugin that has `plugins/<id>/locales/en.ftl`, copy it to
   `plugins/<id>/locales/<tag>.ftl` and translate it.
4. In every `plugins/<id>/plugin.toml`, add `<tag> = "..."` under `[name]` and
   `[description]`, then run `cargo xtask devkey` to sign the manifests again.
5. In `catalog/hardening.json`, add `<tag>` to the `title`, `summary` and
   `breaks` of every item.
6. Run `node scripts/check-locales.mjs <tag>` and `cargo nextest run -p
   ibexwall-proto`. They list what is missing.

The app finds the language by the folder name under `ui/locales`. The
language picker shows each language by its own name. The system tray and the
session agent notifications are in `ui/src-tauri/src/lib.rs` and
`crates/ibexwall-agent/src/main.rs`; add a branch for the language there.

## Rules for the text

- Keep every `{ $variable }`; you may move it within the sentence.
- A choice (`{ $n -> [one] ... *[other] ... }`) puts each variant on its own
  line, or Fluent drops the whole message without a word. The checker
  reports this.
- Do not translate product names, commands, file paths, unit names or
  anything in backticks.
- Do not use the em dash or the en dash.
- Keep the same word for the same idea everywhere (firewall, snapshot,
  hardening). The glossary of each language is the choice already made in its
  `ui.ftl`.
- Tone: calm, plain and short. Say what happens and what the person can do.
