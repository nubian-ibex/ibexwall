import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { CATALOG } from '../lib/hardening';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import type { Transaction } from '../gen/contracts';
import HardeningFlow from './HardeningFlow.svelte';

function setup() {
  i18n.set('en');
  const transport = new FixtureTransport('attention', 0, false);
  let n = 0;
  transport.planChange = async (plugin) => ({ id: `plan-${++n}`, plugin, ops: [] }) as never;
  transport.apply = async (planId: string): Promise<Transaction> => ({
    id: `tx-${planId}`,
    plan_id: planId,
    state: 'pending_confirm',
    started_at: '2026-11-01T12:00:00Z',
    restore_point: 'snapshots/x',
  });
  app.useTransport(transport);
  return transport;
}

// Two items that go to different plugins, so there are two transactions.
const items = (() => {
  const seen = new Set<string>();
  return CATALOG.items
    .filter((item) => !seen.has(item.apply.plugin) && seen.add(item.apply.plugin))
    .slice(0, 2);
})();

async function applied() {
  render(HardeningFlow, { items });
  await fireEvent.click(screen.getByRole('button', { name: /review/i }));
  await fireEvent.click(await screen.findByRole('button', { name: /^apply/i }));
  await screen.findByText(/2 changes are in place/);
}

describe('HardeningFlow', () => {
  beforeEach(() => {
    app.changing = 0;
    app.notice = null;
  });

  it('does not roll back again what a failed undo already rolled back', async () => {
    const transport = setup();
    expect(items.length).toBe(2);
    const calls: string[] = [];
    let failSecond = true;
    transport.rollback = vi.fn(async (id: string) => {
      calls.push(id);
      // Undo goes in reverse: the last transaction first, then the first.
      if (calls.length === 2 && failSecond) {
        failSecond = false;
        throw new TransportError('com.ibexwall.Core.Failed', { reason: 'boom' });
      }
      return { id, state: 'rolled_back' } as Transaction;
    });
    await applied();
    await fireEvent.click(screen.getByRole('button', { name: /undo/i }));
    await screen.findByRole('alert');
    await fireEvent.click(screen.getByRole('button', { name: /undo/i }));
    // Last: ok. First: failed. Retry: only the first again.
    expect(calls).toHaveLength(3);
    expect(calls[0]).not.toBe(calls[1]);
    expect(calls[2]).toBe(calls[1]);
  });

  it('keeps only the unconfirmed ones pending after a failed keep', async () => {
    const transport = setup();
    const confirmed: string[] = [];
    let fail = true;
    transport.confirm = vi.fn(async (id: string) => {
      if (confirmed.length === 1 && fail) {
        fail = false;
        throw new TransportError('com.ibexwall.Core.Failed', { reason: 'boom' });
      }
      confirmed.push(id);
    }) as never;
    await applied();
    await fireEvent.click(screen.getByRole('button', { name: /keep/i }));
    await screen.findByRole('alert');
    await fireEvent.click(screen.getByRole('button', { name: /keep/i }));
    expect(confirmed).toHaveLength(2);
    expect(new Set(confirmed).size).toBe(2);
  });
});
