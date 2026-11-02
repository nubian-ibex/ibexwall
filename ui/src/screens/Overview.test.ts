import { render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { FixtureTransport, type Scenario } from '../lib/fixtures';
import { app } from '../lib/app.svelte';
import { i18n } from '../lib/i18n.svelte';
import Overview from './Overview.svelte';

async function show(scenario: Scenario) {
  app.useTransport(new FixtureTransport(scenario));
  render(Overview);
  await app.refresh();
}

describe('Overview', () => {
  beforeEach(() => i18n.set('en'));

  it('shows a calm attention state with recommendations when checks fail', async () => {
    await show('attention');
    expect(await screen.findByRole('heading', { name: /can be better protected/i })).toBeVisible();
    expect(screen.getByRole('img', { name: /score \d+ out of 100/i })).toBeVisible();
    expect(screen.getByRole('button', { name: /see recommendation/i })).toBeVisible();
    // Cards state their status in words.
    expect(screen.getAllByText('Attention').length).toBeGreaterThan(0);
    // Checks that cannot be assessed yet are admitted, not hidden.
    expect(screen.getByText(/3 checks cannot be assessed yet/i)).toBeVisible();
  });

  it('shows protected when everything is in order', async () => {
    await show('protected');
    expect(
      await screen.findByRole('heading', { name: /your computer is protected/i }),
    ).toBeVisible();
    expect(screen.queryByRole('button', { name: /see recommendation/i })).toBeNull();
  });

  it('offers the first check when nothing has run', async () => {
    await show('empty');
    expect(await screen.findByRole('heading', { name: /check your computer/i })).toBeVisible();
    expect(screen.getByRole('button', { name: /run the first check/i })).toBeVisible();
    expect(screen.getByRole('img', { name: /no score yet/i })).toBeVisible();
  });

  it('explains an unreachable service without alarm and offers a retry', async () => {
    await show('error');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /cannot reach the ibexwall service/i,
    );
    expect(screen.getByText(/protections keep working/i)).toBeVisible();
    expect(screen.getByRole('button', { name: /try again/i })).toBeVisible();
  });

  it('explains missing permission and names the action', async () => {
    await show('denied');
    expect(await screen.findByText(/permission needed/i)).toBeVisible();
    expect(screen.getByText(/com\.ibexwall\.read/)).toBeVisible();
  });

  it('speaks Portuguese when asked', async () => {
    i18n.set('pt-BR');
    await show('attention');
    expect(
      await screen.findByRole('heading', { name: /pode estar mais protegido/i }),
    ).toBeVisible();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /verificar agora/i })).toBeVisible(),
    );
  });
});
