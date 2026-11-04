import { FluentResource } from '@fluent/bundle';
import { beforeEach, describe, expect, it } from 'vitest';
import { has, i18n, messageKeys, t } from './i18n.svelte';
import { relativeTime } from './time';

describe('i18n', () => {
  beforeEach(() => i18n.set('en'));

  it('ships the same message keys in English and Portuguese', () => {
    expect(messageKeys('pt-BR')).toEqual(messageKeys('en'));
  });

  it('formats named arguments and selects plurals', () => {
    expect(t('score-label', { score: 92 })).toBe('Score 92 out of 100');
    i18n.set('pt-BR');
    expect(t('score-label', { score: 92 })).toBe('Pontuação 92 de 100');
    expect(t('overview-not-assessed', { count: 1 })).toContain('1 verificação');
    expect(t('overview-not-assessed', { count: 3 })).toContain('3 verificações');
  });

  it('uses the plugin message catalogs in both languages', () => {
    expect(t('posture-disk-encryption-title')).toBe('The system disk is not encrypted');
    i18n.set('pt-BR');
    expect(t('posture-disk-encryption-title')).toBe('O disco do sistema não está criptografado');
    expect(has('ports-exposed-summary')).toBe(true);
  });

  it('has no message that Fluent would silently drop, in the UI or in any plugin', () => {
    const files = {
      ...import.meta.glob('../../locales/*/ui.ftl', {
        query: '?raw',
        import: 'default',
        eager: true,
      }),
      ...import.meta.glob('../../../plugins/*/locales/*.ftl', {
        query: '?raw',
        import: 'default',
        eager: true,
      }),
    } as Record<string, string>;
    for (const [path, text] of Object.entries(files)) {
      // A message starts at column 0 with a valid identifier; a dot in the
      // id (plugin-system.ports-summary) makes Fluent drop it silently.
      const starts = text
        .split('\n')
        .filter((line) => line !== '' && !/^[\s#-]/.test(line) && !line.startsWith('}'));
      for (const line of starts) {
        expect(line, path).toMatch(/^[a-zA-Z][a-zA-Z0-9_-]*\s*=/);
      }
      expect(new FluentResource(text).body.length, path).toBe(starts.length);
    }
  });

  it('has every "may affect" note of each plugin, in both languages', () => {
    const manifests = import.meta.glob('../../../plugins/*/plugin.toml', {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    expect(Object.keys(manifests).length).toBeGreaterThan(20);
    for (const [, text] of Object.entries(manifests)) {
      const id = /^id = "([^"]+)"/m.exec(text)?.[1] ?? '';
      const keys: string[] = [];
      const block = /may_affect = \[([^\]]*)\]/s.exec(text)?.[1] ?? '';
      for (const match of block.matchAll(/"([^"]+)"/g)) keys.push(match[1]!);
      for (const locale of ['en', 'pt-BR'] as const) {
        i18n.set(locale);
        for (const key of keys) expect(has(key), `${id}: ${key} (${locale})`).toBe(true);
      }
    }
  });

  it('falls back to the key, never to an empty string', () => {
    expect(t('no-such-key')).toBe('no-such-key');
  });

  it('renders untrusted arguments as plain text', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    expect(t('ports-exposed-summary', { process: hostile, proto: 'TCP', port: '22' })).toContain(
      hostile,
    );
  });
});

describe('relativeTime', () => {
  it('says how long ago in the active language', () => {
    const now = new Date('2026-11-01T12:04:00Z');
    expect(relativeTime('2026-11-01T12:00:00Z', 'en', now)).toBe('4 minutes ago');
    expect(relativeTime('2026-11-01T12:00:00Z', 'pt-BR', now)).toBe('há 4 minutos');
    expect(relativeTime('not a date', 'en', now)).toBe('not a date');
  });
});
