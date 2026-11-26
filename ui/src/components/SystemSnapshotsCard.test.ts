import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import SystemSnapshotsCard from './SystemSnapshotsCard.svelte';

const control = () => screen.findByRole('switch', { name: 'System snapshots' });

describe('system snapshots', () => {
  let transport: FixtureTransport;

  beforeEach(() => {
    i18n.set('en');
    transport = new FixtureTransport('attention');
    app.useTransport(transport);
  });

  it('turns on and shows what the service says', async () => {
    render(SystemSnapshotsCard);
    const toggle = await control();
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    await fireEvent.click(toggle);
    await waitFor(() => expect(toggle).toHaveAttribute('aria-checked', 'true'));
  });

  it('cannot be turned on where snapshots cannot be taken, and says why', async () => {
    transport.snapshots = {
      enabled: false,
      available: false,
      reason: 'snapper is not installed',
    };
    render(SystemSnapshotsCard);
    expect(await control()).toBeDisabled();
    expect(screen.getByText(/snapper is not installed/)).toBeVisible();
  });

  it('can still be turned off when snapper stopped working', async () => {
    transport.snapshots = { enabled: true, available: false, reason: 'gone' };
    render(SystemSnapshotsCard);
    expect(await control()).toBeEnabled();
  });
});
