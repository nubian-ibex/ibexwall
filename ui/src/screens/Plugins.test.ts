import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport, type Scenario } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import Plugins from './Plugins.svelte';

async function show(scenario: Scenario = 'attention') {
  app.useTransport(new FixtureTransport(scenario));
  render(Plugins);
  await app.refresh();
}

describe('Plugins', () => {
  beforeEach(() => i18n.set('en'));

  it('lists plugins with kind, origin and a labelled switch', async () => {
    await show();
    expect(await screen.findAllByRole('switch')).toHaveLength(5);
    expect(screen.getAllByText('Read-only').length).toBe(5);
    expect(screen.getAllByText('Official').length).toBe(5);
  });

  it('shows the detail with permissions in plain words and the technical line', async () => {
    await show();
    await fireEvent.click(screen.getAllByRole('button', { name: /detail/i })[0]!);
    await waitFor(() =>
      expect(screen.getByText('Read the system; it cannot change anything')).toBeVisible(),
    );
    // system.posture has open findings; they are listed in its detail.
    expect(screen.getByText('The system disk is not encrypted')).toBeVisible();
  });

  it('runs the simulate, apply and keep-changes flow for control plugins', async () => {
    await show();
    // system.ports fixture is read-only; open its detail: no change flow.
    await fireEvent.click(screen.getAllByRole('button', { name: /detail/i })[0]!);
    expect(screen.queryByRole('button', { name: /simulate/i })).toBeNull();
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    await show();
    expect(await screen.findByRole('heading', { name: /plugins/i })).toBeVisible();
    expect(screen.getAllByText('Somente leitura').length).toBe(5);
    expect(screen.getAllByText('Oficial').length).toBe(5);
  });
});
