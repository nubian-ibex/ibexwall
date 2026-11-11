// Pure helpers for the Apps and network screen. Everything here treats the
// strings it receives (names, paths, domains) as untrusted display text.
import type { AppEntry } from '../gen/contracts';

export type AppFilter = 'all' | 'active' | 'new';

/** "Connected now": activity within the last five minutes. */
export const ACTIVE_WINDOW_SECONDS = 300;
/** "New": first seen within the last day. */
export const NEW_WINDOW_SECONDS = 86_400;

const KINDS = [
  'flatpak',
  'snap',
  'desktop_app',
  'system_service',
  'container',
  'cli',
  'unknown',
] as const;

/** The Fluent key of the badge that says what kind of program this is. */
export function kindKey(app: AppEntry): string {
  const kind = (KINDS as readonly string[]).includes(app.kind) ? app.kind : 'unknown';
  return `apps-kind-${kind}`;
}

const GENERIC_LAST = new Set(['desktop', 'client', 'app', 'application', 'gui', 'qt', 'gtk']);

function capitalize(text: string): string {
  return text.length === 0 ? text : text[0]!.toUpperCase() + text.slice(1);
}

function basename(path: string | null | undefined): string {
  if (!path) return '';
  const trimmed = path.replace(/\/+$/, '');
  return trimmed.slice(trimmed.lastIndexOf('/') + 1);
}

/** What the desktop entries say, by app key (see `getAppInfo`). */
export type AppDisplays = Record<string, { name?: string | null; icon?: string | null }>;

/** A readable name for an app: the desktop entry's own when it has one,
 * else derived from its identity. */
export function displayName(app: AppEntry, displays: AppDisplays = {}): string {
  const given = displays[app.key]?.name?.trim();
  if (given) return given;
  switch (app.kind) {
    case 'flatpak':
    case 'desktop_app': {
      // org.telegram.desktop and com.spotify.Client name the product one
      // segment earlier than the generic last word.
      const parts = app.id.split('.').filter((part) => part !== '');
      let name = parts.pop() ?? app.id;
      if (GENERIC_LAST.has(name.toLowerCase()) && parts.length > 0) name = parts.pop()!;
      return capitalize(name || app.id);
    }
    case 'snap': {
      // snap.<name>.<app>
      const parts = app.id.split('.');
      return capitalize(parts[1] ?? app.id);
    }
    case 'system_service':
      return app.id.replace(/\.service$/, '');
    case 'container':
      return app.id;
    default:
      return basename(app.exe_path) || app.key;
  }
}

/** The letter shown in the app's tile. */
export function initialOf(app: AppEntry, displays: AppDisplays = {}): string {
  const name = displayName(app, displays).trim();
  return name.length === 0 ? '?' : [...name][0]!.toUpperCase();
}

function secondsSince(iso: string, now: Date): number {
  const then = new Date(iso).getTime();
  return Number.isNaN(then) ? Number.POSITIVE_INFINITY : (now.getTime() - then) / 1000;
}

export function isActive(app: AppEntry, now: Date): boolean {
  return secondsSince(app.last_seen, now) <= ACTIVE_WINDOW_SECONDS;
}

export function isNew(app: AppEntry, now: Date): boolean {
  return secondsSince(app.first_seen, now) <= NEW_WINDOW_SECONDS;
}

export function counts(apps: AppEntry[], now: Date): Record<AppFilter, number> {
  return {
    all: apps.length,
    active: apps.filter((app) => isActive(app, now)).length,
    new: apps.filter((app) => isNew(app, now)).length,
  };
}

export function filterApps(
  apps: AppEntry[],
  filter: AppFilter,
  query: string,
  now: Date,
): AppEntry[] {
  const needle = query.trim().toLowerCase();
  return apps.filter((app) => {
    if (filter === 'active' && !isActive(app, now)) return false;
    if (filter === 'new' && !isNew(app, now)) return false;
    if (needle === '') return true;
    return [displayName(app), app.key, app.id, app.exe_path ?? '', app.package ?? ''].some((text) =>
      text.toLowerCase().includes(needle),
    );
  });
}

export type NetMode = 'allow' | 'monitor' | 'ask' | 'block';

/** Kinds the kernel recognises by their cgroup; the rest by executable. */
const CGROUP_KINDS = new Set(['flatpak', 'snap', 'system_service', 'container']);

/**
 * Whether a mode can be chosen for an app. Needs the monitor running; apps
 * identified by their executable also need the kernel's exec tracing, which
 * some kernels withhold (the monitor says so in its reason).
 */
export function modeAvailable(
  app: AppEntry,
  monitor: { running: boolean; reason?: string | null } | null,
  mode?: NetMode,
): boolean {
  return unavailableKey(app, monitor, mode) === null;
}

/**
 * The Fluent key that says why a mode cannot be chosen, or null when it
 * can. Ask cannot hold a container's first packet: it leaves through
 * another network namespace, where the queue rule does not run.
 */
export function unavailableKey(
  app: AppEntry,
  monitor: { running: boolean; reason?: string | null } | null,
  mode?: NetMode,
): string | null {
  if (!monitor?.running) return 'apps-mode-unavailable';
  if (mode === 'ask' && app.kind === 'container') return 'apps-mode-unavailable-container';
  if (CGROUP_KINDS.has(app.kind)) return null;
  return (monitor.reason ?? '').includes('exec capture') ? 'apps-mode-unavailable' : null;
}

/** Blocking is only offered where it works: Flatpak, system-wide. */
export function canBlock(app: AppEntry): boolean {
  return app.kind === 'flatpak';
}
