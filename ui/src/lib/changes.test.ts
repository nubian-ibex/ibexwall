import { afterEach, describe, expect, it, vi } from 'vitest';
import { changes } from './changes.svelte';

const draft = (id: string, count = 1) => ({ id, plugin: 'p', patch: {}, count, label: 'L' });

describe('changes store', () => {
  afterEach(() => {
    changes.close();
    changes.discard();
  });

  it('keeps one list per source and totals what the person sees', () => {
    changes.setSource('a', [draft('1', 2)]);
    changes.setSource('b', [draft('2')]);
    expect(changes.total).toBe(3);
    expect(changes.countFor('a')).toBe(2);
    changes.setSource('a', []);
    expect(changes.total).toBe(1);
  });

  it('discards one source or everything', () => {
    changes.setSource('a', [draft('1')]);
    changes.setSource('b', [draft('2')]);
    changes.discard('a');
    expect(changes.drafts.map((d) => d.source)).toEqual(['b']);
    changes.discard();
    expect(changes.drafts).toEqual([]);
  });

  it('opens the review for what is queued, or for one direct action, and never for nothing', () => {
    changes.review();
    expect(changes.panel).toBeNull();
    changes.setSource('a', [draft('1')]);
    changes.review();
    expect(changes.panel).toHaveLength(1);
    changes.close();
    changes.propose('net.dns', { x: 1 });
    expect(changes.panel).toEqual([
      expect.objectContaining({ source: 'direct', plugin: 'net.dns', patch: { x: 1 } }),
    ]);
  });

  it('tells a screen when the machine changed, until it stops listening', () => {
    const seen = vi.fn();
    const stop = changes.onApplied(seen);
    changes.notify();
    stop();
    changes.notify();
    expect(seen).toHaveBeenCalledTimes(1);
  });
});
