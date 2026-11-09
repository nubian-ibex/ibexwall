import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { i18n } from '../lib/i18n.svelte';
import Settings from './Settings.svelte';

describe('Settings, managed by an organisation', () => {
  beforeEach(() => {
    i18n.set('en');
    app.route = 'settings';
  });

  it('explains the mode when no organisation manages the machine', () => {
    app.managed = false;
    render(Settings);
    expect(screen.getByRole('heading', { name: 'Organisation' })).toBeVisible();
    expect(screen.getByText(/not managed by an organisation/)).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Open the Organisation screen' })).toBeNull();
  });

  it('opens the Organisation screen when one does', async () => {
    app.managed = true;
    render(Settings);
    await fireEvent.click(screen.getByRole('button', { name: 'Open the Organisation screen' }));
    expect(app.route).toBe('organisation');
  });
});
