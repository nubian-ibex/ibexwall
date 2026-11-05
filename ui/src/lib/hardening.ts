import raw from '../../../catalog/hardening.json';
import type { Finding } from '../gen/contracts';

// The catalog is the same file the plugin reads (catalog/hardening.json), so
// what the screen offers and what the machine is judged against cannot drift.

export type Risk = 'low' | 'medium' | 'high';
export type Status = 'applied' | 'open' | 'unknown';

export interface Text {
  en: string;
  'pt-BR': string;
}

export interface Source {
  name: string;
  url: string;
  section: string;
}

export interface Item {
  id: string;
  area: string;
  risk: Risk;
  recommended: boolean;
  title: Text;
  summary: Text;
  breaks: Text | null;
  sources: Source[];
  apply: { plugin: string; patch: Record<string, unknown> };
  doc: string;
}

export const CATALOG = raw as unknown as { version: number; reviewed: string; items: Item[] };

export const AREAS = ['kernel', 'memory', 'filesystem', 'network'] as const;

/** Every item's state, from what `system.hardening` reports. */
export function statusOf(findings: Finding[]): Map<string, Status> {
  const note = findings.find((f) => f.id === 'hardening.state');
  const map = new Map<string, Status>();
  if (!note) return map;
  for (const [key, status] of [
    ['applied', 'applied'],
    ['open', 'open'],
    ['unknown', 'unknown'],
  ] as const) {
    for (const id of (note.args?.[key] ?? '').split(',')) {
      if (id) map.set(id, status);
    }
  }
  return map;
}

/**
 * Joins the patches of the items that go to one plugin: objects merge,
 * lists are united, and two different values for one setting are a conflict
 * (the catalog is tested so this does not happen).
 */
export function mergePatches(patches: Record<string, unknown>[]): Record<string, unknown> {
  const merge = (a: unknown, b: unknown): unknown => {
    if (Array.isArray(a) && Array.isArray(b)) return [...new Set([...a, ...b])];
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      const out: Record<string, unknown> = { ...(a as Record<string, unknown>) };
      for (const [key, value] of Object.entries(b as Record<string, unknown>)) {
        out[key] = key in out ? merge(out[key], value) : value;
      }
      return out;
    }
    if (a === b) return a;
    throw new Error('two items ask for different values of the same setting');
  };
  return patches.reduce<Record<string, unknown>>(
    (acc, p) => merge(acc, p) as Record<string, unknown>,
    {},
  );
}

/** One reviewed change per plugin, in a stable order. */
export function groupByPlugin(items: Item[]): { plugin: string; patch: Record<string, unknown> }[] {
  const byPlugin = new Map<string, Record<string, unknown>[]>();
  for (const item of items) {
    byPlugin.set(item.apply.plugin, [...(byPlugin.get(item.apply.plugin) ?? []), item.apply.patch]);
  }
  return [...byPlugin.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([plugin, patches]) => ({ plugin, patch: mergePatches(patches) }));
}
