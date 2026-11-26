// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Tauri refuses a command a window was not granted, and neither the type
// check nor the fixture transport can see that.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8');
const between = (text: string, start: string, end: string) => text.split(start)[1]!.split(end)[0]!;

const declared = [
  ...between(read('src-tauri/build.rs'), 'const COMMANDS: &[&str] = &[', '];').matchAll(/"(\w+)"/g),
].map((m) => m[1]!);
const handled = between(read('src-tauri/src/lib.rs'), 'generate_handler![', ']')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const granted: string[] = JSON.parse(read('src-tauri/capabilities/main.json')).permissions;
const invoked = [
  ...read('src/lib/tauri-transport.ts').matchAll(/(?:invoke|unwrapped)(?:<[^(]*>)?\(\s*'(\w+)'/g),
].map((m) => m[1]!);

const permission = (command: string) => `allow-${command.replaceAll('_', '-')}`;

describe('the desktop commands', () => {
  it('are declared exactly as handled', () => {
    expect([...declared].sort()).toEqual([...handled].sort());
  });

  it('are all granted to the main window', () => {
    expect(declared.filter((c) => !granted.includes(permission(c)))).toEqual([]);
  });

  it('cover every call the app makes', () => {
    expect(invoked.length).toBeGreaterThan(20);
    expect(invoked.filter((c) => !declared.includes(c))).toEqual([]);
  });
});
