import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { needsWelcome } from '../lib/welcome';
import Welcome from './Welcome.svelte';

async function open() {
  const transport = new FixtureTransport('attention');
  app.useTransport(transport);
  render(Welcome);
  await app.refresh();
  return transport;
}

async function next(times = 1) {
  for (let i = 0; i < times; i += 1) {
    await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  }
}

describe('Welcome', () => {
  beforeEach(() => {
    i18n.set('en');
    localStorage.clear();
    app.route = 'welcome';
  });

  it('explains the password before anything is changed', async () => {
    await open();
    expect(screen.getByRole('heading', { name: 'Welcome to IbexWall' })).toBeVisible();
    expect(screen.getByText(/asks for your password/)).toBeVisible();
    expect(screen.getByText('Step 1 of 5')).toBeVisible();
  });

  it('turns on the chosen recommended protections, and only those', async () => {
    const transport = await open();
    const enable = vi.spyOn(transport, 'setPluginEnabled');
    await next(2);
    const firewall = screen.getByRole('checkbox', { name: 'Firewall' });
    expect(firewall).toBeChecked();
    await fireEvent.click(screen.getByRole('button', { name: 'Turn on the selected ones' }));
    expect(enable).toHaveBeenCalledWith('net.firewall', true);
    expect(enable).not.toHaveBeenCalledWith('net.dns', true);
    expect(await screen.findByText(/turned on/)).toBeVisible();
  });

  it('is shown once: finishing records it and opens the Overview', async () => {
    await open();
    expect(needsWelcome()).toBe(true);
    await next(4);
    await fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(needsWelcome()).toBe(false);
    expect(app.route).toBe('overview');
  });

  it('can be skipped', async () => {
    await open();
    await fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    expect(needsWelcome()).toBe(false);
    expect(app.route).toBe('overview');
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    await open();
    expect(screen.getByRole('heading', { name: 'Boas-vindas ao IbexWall' })).toBeVisible();
  });
});
