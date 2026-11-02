import { render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import History from './History.svelte';

describe('History', () => {
  beforeEach(() => i18n.set('en'));

  it('shows each change with its result and an undo for kept changes', async () => {
    app.useTransport(new FixtureTransport('attention'));
    render(History);
    await app.refresh();
    expect(await screen.findByText('Applied and kept')).toBeVisible();
    expect(screen.getByText('Undone')).toBeVisible();
    expect(screen.getByRole('button', { name: /undo this change/i })).toBeVisible();
  });

  it('explains when nothing has changed yet', async () => {
    app.useTransport(new FixtureTransport('empty'));
    render(History);
    await app.refresh();
    expect(await screen.findByText(/nothing has changed yet/i)).toBeVisible();
  });
});
