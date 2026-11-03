import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppEntry } from '../gen/contracts';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import Apps from './Apps.svelte';

async function open(scenario: ConstructorParameters<typeof FixtureTransport>[0] = 'attention') {
  const transport = new FixtureTransport(scenario);
  app.useTransport(transport);
  render(Apps);
  await app.refresh();
  return transport;
}

describe('Apps screen', () => {
  beforeEach(() => i18n.set('en'));

  it('lists what the monitor saw, with kinds, counts and the New badge', async () => {
    await open();
    const list = await screen.findByRole('region', { name: 'Apps' });
    expect(within(list).getByText('Firefox')).toBeVisible();
    expect(within(list).getByText('Telegram')).toBeVisible();
    expect(within(list).getAllByText('Flatpak').length).toBe(2);
    expect(within(list).getByText('24 destinations · 412 connections')).toBeVisible();
    // Telegram and the downloaded script were first seen minutes ago.
    expect(within(list).getAllByText('New').length).toBe(2);
    expect(screen.getByText('All · 6')).toBeVisible();
  });

  it('says so, and why, when the monitor is off', async () => {
    await open('empty');
    expect(
      await screen.findByText('The connection monitor is off: waiting for ibexwall-monitor'),
    ).toBeVisible();
    expect(screen.getByText(/nothing is blocked while it is off/i)).toBeVisible();
    expect(screen.getByText('No apps seen yet')).toBeVisible();
  });

  it('filters by connected now, new, and the search text', async () => {
    await open();
    await screen.findByText('Firefox');
    await fireEvent.click(screen.getByRole('button', { name: /new · 2/i }));
    expect(screen.queryByText('Firefox')).toBeNull();
    expect(screen.getByText('Telegram')).toBeVisible();
    await fireEvent.click(screen.getByRole('button', { name: /all · 6/i }));
    await fireEvent.input(screen.getByRole('searchbox'), { target: { value: 'spot' } });
    expect(screen.getByText('Spotify')).toBeVisible();
    expect(screen.queryByText('Firefox')).toBeNull();
    await fireEvent.input(screen.getByRole('searchbox'), { target: { value: 'zzz' } });
    expect(screen.getByText('No app matches your search.')).toBeVisible();
  });

  it('shows where an app connects, marking addresses with no known domain', async () => {
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /details for firefox/i }));
    expect(await screen.findByText('search.duckduckgo.com')).toBeVisible();
    expect(screen.getByText('github.com')).toBeVisible();
    expect(screen.getByText('142.250.80.46')).toBeVisible();
    expect(screen.getByText(/no domain known/i)).toBeVisible();
    expect(screen.getByText('Package: firefox')).toBeVisible();
  });

  it('enables only what works: Monitor everywhere, Block for Flatpak apps', async () => {
    await open();
    const firefox = await screen.findByRole('radiogroup', { name: /network mode for firefox/i });
    expect(within(firefox).getByRole('radio', { name: 'Monitor' })).toBeEnabled();
    expect(within(firefox).getByRole('radio', { name: 'Monitor' })).toBeChecked();
    for (const mode of ['Allow', 'Ask', 'Block']) {
      expect(within(firefox).getByRole('radio', { name: mode })).toBeDisabled();
    }
    const telegram = screen.getByRole('radiogroup', { name: /network mode for telegram/i });
    expect(within(telegram).getByRole('radio', { name: 'Block' })).toBeEnabled();
    expect(within(telegram).getByRole('radio', { name: 'Allow' })).toBeDisabled();
  });

  it('turns the Flatpak plugin on, then plans the block for exactly that app', async () => {
    const transport = await open();
    const enable = vi.spyOn(transport, 'setPluginEnabled');
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('button', { name: /details for telegram/i }));
    expect(screen.getByText(/cannot be changed from here/i)).toBeVisible();
    await fireEvent.click(screen.getByRole('button', { name: /block network access/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(enable).toHaveBeenCalledWith('apps.flatpak-network', true);
    expect(plan).toHaveBeenCalledWith('apps.flatpak-network', { app: 'org.telegram.desktop' });
  });

  it('offers no blocking for programs that are not Flatpak apps', async () => {
    await open();
    await fireEvent.click(await screen.findByRole('button', { name: /details for firefox/i }));
    expect(screen.queryByRole('button', { name: /block network access/i })).toBeNull();
    expect(screen.getByText(/arrives with the firewall/i)).toBeVisible();
  });

  it('renders in Portuguese with plurals', async () => {
    i18n.set('pt-BR');
    await open();
    expect(await screen.findByRole('heading', { level: 1, name: 'Apps e rede' })).toBeVisible();
    expect(screen.getByText('1 destino · 1 conexão')).toBeVisible();
    expect(screen.getByText('24 destinos · 412 conexões')).toBeVisible();
    expect(screen.getByRole('button', { name: /conectados agora/i })).toBeVisible();
  });

  it('shows names and paths as plain text, whatever they contain', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const transport = new FixtureTransport('attention');
    vi.spyOn(transport, 'listApps').mockResolvedValue({
      monitor: { running: true },
      apps: [
        {
          key: `cli:/tmp/${hostile}`,
          kind: 'cli',
          id: '',
          exe_path: `/tmp/${hostile}`,
          package: null,
          first_seen: '2026-11-01T00:00:00Z',
          last_seen: '2026-11-01T00:00:00Z',
          connections: 1,
          destinations: 1,
        } satisfies AppEntry,
      ],
    });
    app.useTransport(transport);
    const { container } = render(Apps);
    expect(await screen.findByText(hostile)).toBeVisible();
    expect(container.querySelector('img')).toBeNull();
  });

  it('reports a core that cannot be reached, with a retry', async () => {
    const transport = new FixtureTransport('attention');
    vi.spyOn(transport, 'listApps').mockRejectedValue(new TransportError('unreachable'));
    app.useTransport(transport);
    render(Apps);
    expect(await screen.findByRole('alert')).toBeVisible();
    expect(screen.getByRole('button', { name: /try again/i })).toBeVisible();
  });
});
