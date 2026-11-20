import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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

  it('shows an error with retry instead of loading forever', async () => {
    const transport = new FixtureTransport('attention');
    transport.history = () => Promise.reject(new Error('unreachable'));
    app.useTransport(transport);
    render(History);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeVisible();
  });

  it('offers restore points: create one, see the plan and go back', async () => {
    const transport = new FixtureTransport('attention');
    const apply = vi.spyOn(transport, 'restorePointApply');
    app.useTransport(transport);
    render(History);
    await app.refresh();
    expect(await screen.findByText('Restore points')).toBeVisible();
    expect(screen.getByText(/calm/)).toBeVisible();
    // Create with the name field.
    await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'test' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('test')).toBeVisible();
    // The plan is shown before anything moves, then it goes back.
    await fireEvent.click(screen.getAllByRole('button', { name: 'Go back' })[0]!);
    expect(await screen.findByRole('group', { name: /about to be undone/i })).toBeVisible();
    await fireEvent.click(screen.getByRole('button', { name: 'Undo changes' }));
    await vi.waitFor(() => expect(apply).toHaveBeenCalledWith('calm'));
  });
});
