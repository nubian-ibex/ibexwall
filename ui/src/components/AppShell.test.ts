import { render, screen } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import AppShell from './AppShell.svelte';

const children = createRawSnippet(() => ({ render: () => '<p>screen</p>' }));

async function shell(scenario: 'protected' | 'attention' | 'error' | 'denied') {
  app.useTransport(new FixtureTransport(scenario));
  render(AppShell, { children });
  await app.refresh();
  return screen.getByRole('status');
}

describe('AppShell status', () => {
  beforeEach(() => i18n.set('en'));

  it('says protection is active only when the posture says so', async () => {
    expect(await shell('protected')).toHaveTextContent('Protection active');
  });

  it('says the service runs when the posture needs attention', async () => {
    expect(await shell('attention')).toHaveTextContent('Service running');
  });

  it('says the service is not responding when it cannot be reached', async () => {
    expect(await shell('error')).toHaveTextContent('Service not responding');
  });

  it('says there is no access when reading is refused', async () => {
    expect(await shell('denied')).toHaveTextContent('No access to the service');
  });

  it('says the service works in part when something is degraded', async () => {
    app.useTransport(new FixtureTransport('protected'));
    render(AppShell, { children });
    await app.refresh();
    app.info = {
      status: 'ready',
      data: {
        api: 1,
        degraded: ['monitor'],
        distro: 'fedora',
        features: [],
        kernel: '',
        version: '',
      },
    };
    await Promise.resolve();
    expect(screen.getByRole('status')).toHaveTextContent('Service partly working');
  });

  it('shows Organisation only when an organisation manages the machine', async () => {
    app.useTransport(new FixtureTransport('protected'));
    render(AppShell, { children });
    await app.refresh();
    expect(screen.queryByRole('button', { name: 'Organisation' })).toBeNull();
    app.managed = true;
    expect(await screen.findByRole('button', { name: 'Organisation' })).toBeVisible();
  });
});
