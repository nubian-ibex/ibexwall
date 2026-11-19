import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { changes } from '../lib/changes.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import ChangeLayer from './ChangeLayer.svelte';

const op = { target: '/etc/x', op: 'file_write' };

function transport() {
  const t = new FixtureTransport('attention', 0, false);
  let n = 0;
  t.planChange = (async (plugin: string) => ({
    id: `p${++n}`,
    plugin,
    ops: [op],
  })) as never;
  app.useTransport(t);
  return t;
}

async function open(drafts: { plugin: string }[], planned = true) {
  render(ChangeLayer);
  changes.setSource(
    'test',
    drafts.map((d, i) => ({ id: `d${i}`, plugin: d.plugin, patch: {}, count: 1, label: 'T' })),
  );
  changes.review();
  await screen.findByRole('dialog');
  // Wait for the plans: the Apply button is disabled until they are ready.
  if (planned) await screen.findByText(/Nothing has changed yet/);
}

describe('ReviewPanel', () => {
  beforeEach(() => {
    i18n.set('en');
    app.changing = 0;
    app.notice = null;
  });
  afterEach(() => vi.useRealTimers());

  it('shows the three steps, the plan and nothing applied while reviewing', async () => {
    const t = transport();
    const apply = vi.spyOn(t, 'apply');
    await open([{ plugin: 'a' }]);
    expect(screen.getByRole('list', { name: 'Steps' })).toBeVisible();
    expect(screen.getByText('Review').closest('li')).toHaveAttribute('aria-current', 'step');
    expect(await screen.findByText(/Nothing has changed yet/)).toBeVisible();
    expect(await screen.findByRole('button', { name: 'Apply 1 change' })).toBeEnabled();
    expect(apply).not.toHaveBeenCalled();
  });

  it('refuses to apply when a plan fails, and says why', async () => {
    const t = transport();
    t.planChange = (async () => {
      throw Object.assign(new Error('x'), {});
    }) as never;
    await open([{ plugin: 'a' }], false);
    expect(await screen.findByRole('alert')).toBeVisible();
    expect(screen.getByRole('button', { name: /^apply/i })).toBeDisabled();
  });

  it('applies in order, then keeps with one confirm per transaction', async () => {
    const t = transport();
    const order: string[] = [];
    t.apply = (async (id: string) => {
      order.push(`apply ${id}`);
      return {
        id: `tx-${id}`,
        plan_id: id,
        state: 'pending_confirm',
        started_at: '',
        confirm_deadline: new Date(Date.now() + 60_000).toISOString(),
        restore_point: '',
      };
    }) as never;
    t.confirm = (async (id: string) => {
      order.push(`confirm ${id}`);
    }) as never;
    await open([{ plugin: 'a' }, { plugin: 'b' }]);
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply 2 changes' }));
    expect(await screen.findByRole('button', { name: 'Keep changes' })).toBeVisible();
    expect(order).toEqual(['apply p1', 'apply p2']);
    await fireEvent.click(screen.getByRole('button', { name: 'Keep changes' }));
    expect(await screen.findByText(/2 changes are in place/)).toBeVisible();
    expect(order.slice(2)).toEqual(['confirm tx-p1', 'confirm tx-p2']);
  });

  it('undoes in reverse, and a failure part-way leaves a retry that repeats only what is open', async () => {
    const t = transport();
    t.apply = (async (id: string) => ({
      id: `tx-${id}`,
      plan_id: id,
      state: 'pending_confirm',
      started_at: '',
      confirm_deadline: new Date(Date.now() + 60_000).toISOString(),
      restore_point: '',
    })) as never;
    const calls: string[] = [];
    let fail = true;
    t.rollback = (async (id: string) => {
      calls.push(id);
      if (id === 'tx-p1' && fail) throw new Error('boom');
    }) as never;
    await open([{ plugin: 'a' }, { plugin: 'b' }]);
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply 2 changes' }));
    await screen.findByRole('button', { name: 'Keep changes' });
    await fireEvent.click(screen.getByRole('button', { name: 'Undo changes' }));
    await screen.findByRole('alert');
    expect(calls).toEqual(['tx-p2', 'tx-p1']);
    fail = false;
    await fireEvent.click(screen.getByRole('button', { name: 'Undo changes' }));
    await screen.findByText('All changes were undone.');
    // The retry did not roll back the one that was already undone.
    expect(calls).toEqual(['tx-p2', 'tx-p1', 'tx-p1']);
  });

  it('sends one confirm for a double click on Keep', async () => {
    const t = transport();
    t.apply = (async (id: string) => ({
      id: `tx-${id}`,
      plan_id: id,
      state: 'pending_confirm',
      started_at: '',
      confirm_deadline: new Date(Date.now() + 60_000).toISOString(),
      restore_point: '',
    })) as never;
    let release: () => void = () => {};
    const confirm = vi.fn(() => new Promise<void>((resolve) => (release = resolve)));
    t.confirm = confirm as never;
    await open([{ plugin: 'a' }]);
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply 1 change' }));
    const keep = await screen.findByRole('button', { name: 'Keep changes' });
    await fireEvent.click(keep);
    await fireEvent.click(keep);
    expect(confirm).toHaveBeenCalledTimes(1);
    release();
  });

  it('says the changes were undone when the deadline passes', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const t = transport();
    t.apply = (async (id: string) => ({
      id: `tx-${id}`,
      plan_id: id,
      state: 'pending_confirm',
      started_at: '',
      confirm_deadline: new Date(Date.now() + 60_000).toISOString(),
      restore_point: '',
    })) as never;
    await open([{ plugin: 'a' }]);
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply 1 change' }));
    await screen.findByRole('alertdialog');
    await vi.advanceTimersByTimeAsync(61_000);
    expect(await screen.findByText(/the changes were undone/i)).toBeVisible();
  });

  it('closes on Escape while reviewing, but not while the changes wait to be kept', async () => {
    const t = transport();
    t.apply = (async (id: string) => ({
      id: `tx-${id}`,
      plan_id: id,
      state: 'pending_confirm',
      started_at: '',
      confirm_deadline: new Date(Date.now() + 60_000).toISOString(),
      restore_point: '',
    })) as never;
    await open([{ plugin: 'a' }]);
    await fireEvent.click(await screen.findByRole('button', { name: 'Apply 1 change' }));
    await screen.findByRole('button', { name: 'Keep changes' });
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.getByRole('dialog')).toBeVisible();
  });

  it('closes on Escape before anything is applied', async () => {
    transport();
    await open([{ plugin: 'a' }]);
    await screen.findByRole('button', { name: 'Apply 1 change' });
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
