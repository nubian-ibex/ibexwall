import { fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { i18n } from '../lib/i18n.svelte';
import ConfirmCountdown from './ConfirmCountdown.svelte';

describe('ConfirmCountdown', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-01T12:00:00Z'));
    i18n.set('en');
  });
  afterEach(() => vi.useRealTimers());

  it('counts down to the transaction deadline, not from when it mounted', async () => {
    render(ConfirmCountdown, {
      deadline: '2026-11-01T12:00:20Z',
      onkeep: () => {},
      oncancel: () => {},
    });
    expect(screen.getByText(/20 s left/)).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(5000);
    expect(screen.getByText(/15 s left/)).toBeInTheDocument();
  });

  it('reports the expiry once, at zero', async () => {
    const onexpire = vi.fn();
    render(ConfirmCountdown, {
      deadline: '2026-11-01T12:00:03Z',
      onkeep: () => {},
      oncancel: () => {},
      onexpire,
    });
    await vi.advanceTimersByTimeAsync(2000);
    expect(onexpire).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(5000);
    expect(onexpire).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/0 s left/)).toBeInTheDocument();
  });

  it('disables both buttons while busy', () => {
    const onkeep = vi.fn();
    render(ConfirmCountdown, { busy: true, onkeep, oncancel: () => {} });
    expect(screen.getByRole('button', { name: 'Keep changes' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Undo changes' })).toBeDisabled();
  });

  it('falls back to the given seconds without a deadline', () => {
    render(ConfirmCountdown, { seconds: 30, onkeep: () => {}, oncancel: () => {} });
    expect(screen.getByText(/30 s left/)).toBeInTheDocument();
  });
});
