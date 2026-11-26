import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import StateFileCard from './StateFileCard.svelte';

async function choose(text = '{"schema":1}') {
  const input = screen.getByLabelText('Choose a file to import');
  await fireEvent.change(input, {
    target: { files: [new File([text], 'state.json', { type: 'application/json' })] },
  });
}

describe('the settings file', () => {
  let transport: FixtureTransport;

  beforeEach(() => {
    i18n.set('en');
    transport = new FixtureTransport('attention');
    app.useTransport(transport);
  });

  it('says where the export went', async () => {
    render(StateFileCard);
    await fireEvent.click(screen.getByRole('button', { name: 'Save to a file' }));
    expect(await screen.findByText(/Saved to \/home\/user\/ibexwall-state/)).toBeVisible();
  });

  it('shows what would change and imports only when told to', async () => {
    const apply = vi.spyOn(transport, 'applyImport');
    render(StateFileCard);
    await choose();
    expect(await screen.findByText('net.dns: provider')).toBeVisible();
    expect(screen.getByText('net.vpn: turn off')).toBeVisible();
    expect(screen.getByText(/Locked by your organisation.*net.firewall.mode/)).toBeVisible();
    expect(apply).not.toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Import' });
    await waitFor(() => expect(confirm).toBeEnabled());
    await fireEvent.click(confirm);
    expect(await screen.findByText(/^Imported\./)).toBeVisible();
    expect(apply).toHaveBeenCalledWith('{"schema":1}');
  });

  it('offers nothing to import when the file matches', async () => {
    vi.spyOn(transport, 'previewImport').mockResolvedValue({
      dry_run: true,
      settings: [],
      plugins: [],
      locked: [],
    });
    render(StateFileCard);
    await choose();
    expect(await screen.findByText(/matches this computer/)).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Import' })).toBeNull();
  });

  it('says why a file is refused', async () => {
    vi.spyOn(transport, 'previewImport').mockRejectedValue(
      new TransportError('com.ibexwall.Core.InvalidArgument', { reason: 'not a JSON document' }),
    );
    render(StateFileCard);
    await choose('nope');
    expect(await screen.findByRole('alert')).toHaveTextContent('not a JSON document');
  });
});
