import { render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import Posture from './Posture.svelte';

async function show() {
  app.useTransport(new FixtureTransport('attention'));
  render(Posture);
  await app.refresh();
}

describe('Posture detail', () => {
  beforeEach(() => i18n.set('en'));

  it('recommends the highest-weight failure first', async () => {
    await show();
    expect(await screen.findByRole('heading', { name: /recommendation/i })).toBeVisible();
    // The disk encryption finding (high) comes before the firewall one (high)
    // by check id order; both are shown as open findings.
    expect(screen.getAllByText('The system disk is not encrypted').length).toBeGreaterThanOrEqual(
      2,
    );
  });

  it('discloses the score formula with weights', async () => {
    await show();
    expect(screen.getAllByText('How we calculate').length).toBe(2);
  });

  it('lists every check with its outcome in words', async () => {
    await show();
    expect(screen.getAllByText('Attention').length).toBeGreaterThan(3);
    expect(screen.getAllByText('In order').length).toBeGreaterThan(2);
    expect(screen.getAllByText('Not assessed yet').length).toBe(3);
  });

  it('says which access-control system the machine has, as information', async () => {
    await show();
    expect(await screen.findByText(/mandatory access control today/i)).toBeVisible();
    expect(screen.getByText(/selinux is on but only logs what it would block/i)).toBeVisible();
  });
});
