#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Screenshots of the built interface (with its fixtures) in every language, for
// the website and the documentation. The words on the buttons come from the
// locale files, so a new language needs nothing here.
//
//   pnpm build && node scripts/screenshots.mjs ../../ibexwall-website/public/shots
import { spawn } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const here = dirname(fileURLToPath(import.meta.url));
const ui = join(here, '..');
const out = resolve(process.argv[2] ?? join(ui, 'screenshots'));
const port = 4179;
const locales = readdirSync(join(ui, 'locales'));

const label = (locale, key) => {
  const text = readFileSync(join(ui, 'locales', locale, 'ui.ftl'), 'utf8');
  const match = new RegExp(`^${key} = (.+)$`, 'm').exec(text);
  if (!match) throw new Error(`${locale}: no ${key}`);
  return match[1].trim();
};

const server = spawn(
  'pnpm',
  ['exec', 'vite', 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
  {
    cwd: ui,
    stdio: 'ignore',
  },
);
const stop = () => server.kill();
process.on('exit', stop);

async function waitUp() {
  for (let i = 0; i < 60; i += 1) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/`)).ok) return;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('the preview server did not start');
}

await waitUp();
const browser = await chromium.launch();
const screens = [
  ['overview', 'nav-overview'],
  ['hardening', 'nav-hardening'],
  ['firewall', 'nav-firewall'],
  ['dns', 'nav-dns'],
  ['assistant', 'nav-assistant'],
  ['apps', 'nav-apps'],
];

for (const locale of locales) {
  const dir = join(out, locale);
  mkdirSync(dir, { recursive: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    colorScheme: 'light',
    locale,
  });
  const page = await context.newPage();
  await page.addInitScript((l) => localStorage.setItem('ibexwall.locale', l), locale);
  await page.goto(`http://127.0.0.1:${port}/?scenario=attention`);
  await page.getByRole('heading', { level: 1 }).first().waitFor();
  for (const [name, key] of screens) {
    await page
      .getByRole('button', { name: label(locale, key), exact: true })
      .first()
      .click();
    await page.getByRole('heading', { level: 1 }).first().waitFor();
    await page.waitForTimeout(250);
    await page.screenshot({ path: join(dir, `${name}.png`) });
  }
  await context.close();
  console.log(`${locale}: ${screens.length} screenshots`);
}
await browser.close();
stop();
