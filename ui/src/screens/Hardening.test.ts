import { renderScreen } from '../test-utils';
import { fireEvent, screen, within } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { changes } from '../lib/changes.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { CATALOG, groupByPlugin, mergePatches, statusOf } from '../lib/hardening';
import { i18n } from '../lib/i18n.svelte';
import Hardening from './Hardening.svelte';

async function open(transport = new FixtureTransport('attention')) {
  app.useTransport(transport);
  renderScreen(Hardening);
  await screen.findByText(/of \d+ recommended settings are already in place|de \d+ configurações/i);
  return transport;
}

describe('Hardening screen', () => {
  beforeEach(() => i18n.set('en'));

  it('shows each setting with where it comes from, what it can break and whether it is in place', async () => {
    await open();
    expect(screen.getByText(/2 of 26 recommended settings are already in place/i)).toBeVisible();
    // What is in place folds away; open it to read the same rows.
    await fireEvent.click(screen.getByText('2 already in place'));
    const kptr = screen.getByText('Hide kernel addresses').closest('li') as HTMLElement;
    expect(within(kptr).getByText('In place')).toBeVisible();
    expect(within(kptr).getByRole('link', { name: /madaidans/i })).toHaveAttribute(
      'href',
      expect.stringContaining('#sysctl-kernel'),
    );
    const ns = screen.getByText(/turn off unprivileged sandboxes/i).closest('li') as HTMLElement;
    expect(within(ns).getByText(/flatpak, the chromium and firefox sandboxes/i)).toBeVisible();
    expect(within(ns).getByText('Can break things')).toBeVisible();
    const sysrq = screen.getByText(/turn off the sysrq/i).closest('li') as HTMLElement;
    expect(within(sysrq).getByText('Cannot tell')).toBeVisible();
  });

  it('starts with only what is safe and missing ticked, and never a risky or applied one', async () => {
    await open();
    // The applied section holds one of the boxes this test inspects.
    await fireEvent.click(screen.getByText('2 already in place'));
    const box = (name: RegExp) => screen.getByRole('checkbox', { name }) as HTMLInputElement;
    expect(box(/hide the kernel log|keep the kernel log/i).checked).toBe(true);
    expect(box(/hide kernel addresses/i).checked).toBe(false);
    expect(box(/hide kernel addresses/i).disabled).toBe(true);
    expect(box(/turn off unprivileged sandboxes/i).checked).toBe(false);
    expect(box(/turn off bluetooth/i).checked).toBe(false);
    expect(box(/do not run programs from \/tmp/i).checked).toBe(false);
    for (const item of CATALOG.items.filter((i) => i.risk === 'high')) {
      expect(item.recommended).toBe(false);
    }
  });

  it('plans one change per plugin with the ticked settings joined, and applies nothing by reviewing', async () => {
    const transport = new FixtureTransport('attention');
    const plan = vi.spyOn(transport, 'planChange');
    const apply = vi.spyOn(transport, 'apply');
    await open(transport);
    // The safe, missing modules are already ticked: both go to one plan.
    await fireEvent.click(await screen.findByRole('button', { name: /review and apply/i }));
    const calls = plan.mock.calls;
    const sysctl = calls.find(([plugin]) => plugin === 'system.sysctl');
    const modules = calls.find(([plugin]) => plugin === 'system.modules');
    expect(sysctl).toBeDefined();
    expect(Object.keys((sysctl![1] as { keys: Record<string, string> }).keys)).toContain(
      'kernel.dmesg_restrict',
    );
    expect(modules![1]).toEqual({ block: expect.arrayContaining(['net-protocols', 'vivid']) });
    expect(apply).not.toHaveBeenCalled();
    expect(await screen.findByRole('dialog')).toBeVisible();
  });

  it('queues what is ticked in the change bar, with a count that follows the ticks', async () => {
    await open();
    const before = changes.total;
    expect(before).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: /changes ready/i })).toBeVisible();
    await fireEvent.click(screen.getByRole('checkbox', { name: /turn off bluetooth/i }));
    expect(changes.total).toBe(before + 1);
    await fireEvent.click(screen.getByRole('button', { name: /discard/i }));
    expect(changes.total).toBe(0);
  });

  it('links each setting to its page on the site', async () => {
    await open();
    // The first item in place (the applied section) is the kernel one.
    await fireEvent.click(screen.getByText('2 already in place'));
    const links = screen.getAllByRole('link', { name: /more about this setting/i });
    expect(links.length).toBeGreaterThan(5);
    const kptr = screen.getByText('Hide kernel addresses').closest('li') as HTMLElement;
    const link = within(kptr).getByRole('link', { name: /more about this setting/i });
    expect(link).toHaveAttribute('href', 'https://ibexwall.com/hardening/kernel.kptr-restrict');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    await open();
    expect(screen.getByRole('heading', { level: 1, name: 'Hardening' })).toBeVisible();
    await fireEvent.click(screen.getByText('2 já em vigor'));
    expect(screen.getByText('Esconder endereços do kernel')).toBeVisible();
  });
});

describe('hardening catalog helpers', () => {
  it('reads the three lists from the plugin finding', () => {
    const map = statusOf([
      { id: 'hardening.state', args: { applied: 'a,b', open: 'c', unknown: '' } } as never,
    ]);
    expect([map.get('a'), map.get('c'), map.get('zzz')]).toEqual(['applied', 'open', undefined]);
  });

  it('joins patches: objects merge, lists unite, and a real conflict is refused', () => {
    expect(mergePatches([{ keys: { a: '1' } }, { keys: { b: '2' } }])).toEqual({
      keys: { a: '1', b: '2' },
    });
    expect(mergePatches([{ block: ['x'] }, { block: ['y', 'x'] }])).toEqual({ block: ['x', 'y'] });
    expect(() => mergePatches([{ keys: { a: '1' } }, { keys: { a: '2' } }])).toThrow();
  });

  it('never gives two items the same setting with different values', () => {
    const seen = new Map<string, string>();
    for (const item of CATALOG.items.filter((i) => i.apply.plugin === 'system.sysctl')) {
      for (const [key, value] of Object.entries(
        (item.apply.patch as { keys: Record<string, string> }).keys,
      )) {
        expect(seen.get(key) ?? value, key).toBe(value);
        seen.set(key, value);
      }
    }
    expect(() => groupByPlugin(CATALOG.items.filter((i) => i.recommended))).not.toThrow();
  });
});
