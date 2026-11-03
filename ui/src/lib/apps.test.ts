import { describe, expect, it } from 'vitest';
import type { AppEntry } from '../gen/contracts';
import {
  canBlock,
  counts,
  displayName,
  filterApps,
  initialOf,
  isActive,
  isNew,
  kindKey,
} from './apps';

const NOW = new Date('2026-11-03T12:00:00Z');

const app = (over: Partial<AppEntry>): AppEntry => ({
  key: 'cli:/usr/bin/curl',
  kind: 'cli',
  id: '',
  exe_path: '/usr/bin/curl',
  package: 'curl',
  first_seen: '2026-11-01T00:00:00Z',
  last_seen: '2026-11-03T11:58:00Z',
  connections: 3,
  destinations: 2,
  mode: 'monitor',
  ...over,
});

describe('displayName', () => {
  it('derives a readable name from each kind of identity', () => {
    expect(displayName(app({ kind: 'flatpak', id: 'org.mozilla.firefox' }))).toBe('Firefox');
    expect(displayName(app({ kind: 'desktop_app', id: 'firefox' }))).toBe('Firefox');
    expect(displayName(app({ kind: 'flatpak', id: 'org.telegram.desktop' }))).toBe('Telegram');
    expect(displayName(app({ kind: 'flatpak', id: 'com.spotify.Client' }))).toBe('Spotify');
    // Nothing before the generic word: keep it rather than show nothing.
    expect(displayName(app({ kind: 'flatpak', id: 'desktop' }))).toBe('Desktop');
    expect(displayName(app({ kind: 'snap', id: 'snap.snap-store.ubuntu-software' }))).toBe(
      'Snap-store',
    );
    expect(displayName(app({ kind: 'system_service', id: 'sshd.service' }))).toBe('sshd');
    expect(displayName(app({ kind: 'container', id: 'container:0123456789ab' }))).toBe(
      'container:0123456789ab',
    );
    expect(displayName(app({}))).toBe('curl');
    expect(displayName(app({ kind: 'unknown', exe_path: null, key: 'unknown:?' }))).toBe(
      'unknown:?',
    );
  });

  it('picks a letter, even for odd names', () => {
    expect(initialOf(app({}))).toBe('C');
    expect(initialOf(app({ kind: 'unknown', exe_path: '/tmp/éclair' }))).toBe('É');
    expect(initialOf(app({ kind: 'unknown', exe_path: null, key: '' }))).toBe('?');
  });
});

describe('kinds, filters and search', () => {
  it('maps every known kind to a label and falls back for the rest', () => {
    expect(kindKey(app({ kind: 'flatpak' }))).toBe('apps-kind-flatpak');
    expect(kindKey(app({ kind: 'system_service' }))).toBe('apps-kind-system_service');
    expect(kindKey(app({ kind: 'something-new' }))).toBe('apps-kind-unknown');
  });

  it('knows what is connected now and what is new', () => {
    expect(isActive(app({}), NOW)).toBe(true);
    expect(isActive(app({ last_seen: '2026-11-03T11:00:00Z' }), NOW)).toBe(false);
    expect(isActive(app({ last_seen: 'garbage' }), NOW)).toBe(false);
    expect(isNew(app({ first_seen: '2026-11-03T08:00:00Z' }), NOW)).toBe(true);
    expect(isNew(app({}), NOW)).toBe(false);
  });

  it('counts and filters consistently', () => {
    const apps = [
      app({ key: 'a', id: 'a' }),
      app({ key: 'b', last_seen: '2026-11-02T00:00:00Z', first_seen: '2026-11-03T10:00:00Z' }),
    ];
    expect(counts(apps, NOW)).toEqual({ all: 2, active: 1, new: 1 });
    expect(filterApps(apps, 'active', '', NOW).map((a) => a.key)).toEqual(['a']);
    expect(filterApps(apps, 'new', '', NOW).map((a) => a.key)).toEqual(['b']);
  });

  it('searches name, key, executable and package without caring about case', () => {
    const apps = [
      app({
        key: 'flatpak:org.a.Telegram',
        kind: 'flatpak',
        id: 'org.a.Telegram',
        exe_path: null,
        package: null,
      }),
      app({}),
    ];
    expect(filterApps(apps, 'all', 'TELEG', NOW)).toHaveLength(1);
    expect(filterApps(apps, 'all', '/usr/bin', NOW)).toHaveLength(1);
    expect(filterApps(apps, 'all', 'curl', NOW)).toHaveLength(1);
    expect(filterApps(apps, 'all', '  ', NOW)).toHaveLength(2);
    expect(filterApps(apps, 'all', 'zzz', NOW)).toHaveLength(0);
  });

  it('offers blocking only for Flatpak apps', () => {
    expect(canBlock(app({ kind: 'flatpak' }))).toBe(true);
    for (const kind of ['snap', 'cli', 'system_service', 'container', 'desktop_app']) {
      expect(canBlock(app({ kind }))).toBe(false);
    }
  });
});
