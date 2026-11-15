import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import ChangeFlow from './ChangeFlow.svelte';

describe('ChangeFlow', () => {
  beforeEach(() => {
    i18n.set('en');
    app.changing = 0;
    app.notice = null;
  });
  afterEach(() => vi.useRealTimers());

  it('sends one confirm for a double click on Keep', async () => {
    const transport = new FixtureTransport('attention', 0, false);
    app.useTransport(transport);
    let release: () => void = () => {};
    const confirm = vi.fn(() => new Promise<void>((resolve) => (release = resolve)));
    transport.confirm = confirm;
    transport.planChange = async () => ({
      id: 'p1',
      plugin: 'x',
      ops: [{ target: '/etc/x', op: 'file_write' }],
    });
    render(ChangeFlow, { plugin: 'x', patch: {} });
    await fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /^confirm$/i }));
    const keep = await screen.findByRole('button', { name: 'Keep changes' });
    await fireEvent.click(keep);
    await fireEvent.click(keep);
    expect(confirm).toHaveBeenCalledTimes(1);
    release();
  });

  it('shows the change as undone when the deadline passes', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    await startChangeWithOps();
    await fireEvent.click(await screen.findByRole('button', { name: /^confirm$/i }));
    await screen.findByRole('alertdialog');
    await vi.advanceTimersByTimeAsync(61_000);
    expect(await screen.findByText('Changes undone')).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });
});

async function startChangeWithOps() {
  const transport = new FixtureTransport('attention', 0, false);
  transport.planChange = async () => ({
    id: 'p1',
    plugin: 'x',
    ops: [{ target: '/etc/x', op: 'file_write' }],
  });
  app.useTransport(transport);
  render(ChangeFlow, { plugin: 'x', patch: {} });
  await fireEvent.click(screen.getByRole('button', { name: /^apply$/i }));
}
