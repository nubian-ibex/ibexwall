#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks every translation against the English source: same message ids in
// the same order, same variables, valid Fluent, no em or en dashes.
// Usage: node scripts/check-locales.mjs [locale ...]   (default: all but en)
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { FluentResource } = createRequire(join(root, 'ui/package.json'))('@fluent/bundle');

const uiLocales = readdirSync(join(root, 'ui/locales')).filter((d) => d !== 'en');
const wanted = process.argv.length > 2 ? process.argv.slice(2) : uiLocales;
const plugins = readdirSync(join(root, 'plugins')).filter((p) =>
  existsSync(join(root, 'plugins', p, 'locales', 'en.ftl')),
);

function parse(text, label, problems) {
  const resource = new FluentResource(text);
  const ids = [];
  const vars = {};
  for (const entry of resource.body) {
    if (entry.id === undefined) {
      problems.push(`${label}: invalid Fluent near: ${JSON.stringify(String(entry.content ?? entry).slice(0, 80))}`);
      continue;
    }
    ids.push(entry.id);
    const found = new Set();
    const walk = (node) => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === 'object') {
        if (node.type === 'var') found.add(node.name);
        Object.values(node).forEach(walk);
      }
    };
    walk(entry.value);
    for (const attr of Object.values(entry.attributes ?? {})) walk(attr);
    vars[entry.id] = [...found].sort().join(',');
  }
  if (/[–—]/.test(text)) problems.push(`${label}: contains an en or em dash`);
  return { ids, vars };
}

let problems = [];
function compare(enPath, trPath, label) {
  if (!existsSync(trPath)) {
    problems.push(`${label}: missing file`);
    return;
  }
  const local = [];
  const en = parse(readFileSync(enPath, 'utf8'), enPath, local);
  const tr = parse(readFileSync(trPath, 'utf8'), label, local);
  problems.push(...local);
  const missing = en.ids.filter((id) => !tr.ids.includes(id));
  const extra = tr.ids.filter((id) => !en.ids.includes(id));
  if (missing.length) problems.push(`${label}: missing ${missing.slice(0, 8).join(', ')}${missing.length > 8 ? ` (+${missing.length - 8})` : ''}`);
  if (extra.length) problems.push(`${label}: not in English: ${extra.slice(0, 8).join(', ')}`);
  for (const id of en.ids) {
    if (tr.vars[id] !== undefined && tr.vars[id] !== en.vars[id]) {
      problems.push(`${label}: ${id} uses variables [${tr.vars[id]}] but English uses [${en.vars[id]}]`);
    }
  }
}

for (const locale of wanted) {
  compare(join(root, 'ui/locales/en/ui.ftl'), join(root, 'ui/locales', locale, 'ui.ftl'), `ui/locales/${locale}/ui.ftl`);
  for (const plugin of plugins) {
    compare(
      join(root, 'plugins', plugin, 'locales/en.ftl'),
      join(root, 'plugins', plugin, 'locales', `${locale}.ftl`),
      `plugins/${plugin}/locales/${locale}.ftl`,
    );
  }
}
// Every key the interface asks for by its literal name must exist in
// English: a missing one shows its id on screen instead of a text.
function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(svelte|ts)$/.test(entry.name) && !/\.test\.ts$/.test(entry.name) ? [path] : [];
  });
}
{
  const english = new Set(parse(readFileSync(join(root, 'ui/locales/en/ui.ftl'), 'utf8'), 'en', []).ids);
  for (const file of sourceFiles(join(root, 'ui/src'))) {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/\bt\(\s*['"]([a-z0-9][a-z0-9-]*)['"]/g)) {
      if (!english.has(match[1])) problems.push(`${file.slice(root.length + 1)}: uses ${match[1]}, which is not in English`);
    }
    for (const match of text.matchAll(/\bkey:\s*['"]([a-z][a-z0-9-]*)['"]/g)) {
      if (match[1].startsWith('nav-') && !english.has(match[1])) {
        problems.push(`${file.slice(root.length + 1)}: uses ${match[1]}, which is not in English`);
      }
    }
  }
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(`\n${problems.length} problem(s)`);
  process.exit(1);
}
console.log(`ok: ${wanted.join(', ')}`);
