import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import PromptDialog from './PromptDialog.svelte';

async function open(withPrompt = true, locale: 'en' | 'pt-BR' = 'en') {
  i18n.set(locale);
  const transport = new FixtureTransport('attention', 0, withPrompt);
  app.useTransport(transport);
  render(PromptDialog);
  await app.refreshPrompts();
  return transport;
}

describe('PromptDialog', () => {
  beforeEach(() => {
    app.prompts = [];
  });

  it('shows nothing when no connection is held', async () => {
    await open(false);
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });

  it('names the app, the destination and the port, and focuses the decision', async () => {
    await open();
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveAccessibleName('curl wants to access the internet');
    expect(dialog).toHaveAccessibleDescription(/example\.com:443/);
    await vi.waitFor(() => expect(screen.getByRole('button', { name: 'Allow' })).toHaveFocus());
  });

  it('starts from the narrowest scope', async () => {
    await open();
    expect(await screen.findByRole('radio', { name: 'Only this time' })).toBeChecked();
  });

  it('sends the decision with the scope chosen, then closes', async () => {
    const transport = await open();
    const answer = vi.spyOn(transport, 'answerPrompt');
    await fireEvent.click(await screen.findByRole('radio', { name: 'Only for this destination' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Block' }));
    expect(answer).toHaveBeenCalledWith('1', 'block', 'destination');
    await vi.waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
  });

  it('keeps the question and says so when the answer cannot be sent', async () => {
    const transport = await open();
    vi.spyOn(transport, 'answerPrompt').mockRejectedValue(new TransportError('unreachable'));
    await fireEvent.click(await screen.findByRole('button', { name: 'Allow' }));
    expect(
      await screen.findByText('Could not send the answer. It may have expired.'),
    ).toBeVisible();
  });

  it('shows how long is left before the default applies', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-01T12:00:10Z'));
    try {
      await open();
      expect(
        await screen.findByText('No answer in 20 s, the connection goes through.'),
      ).toBeVisible();
    } finally {
      vi.useRealTimers();
    }
  });

  it('counts the questions still waiting', async () => {
    const transport = await open();
    const first = (await transport.listPrompts())[0]!;
    app.prompts = [first, { ...first, id: '2' }, { ...first, id: '3' }];
    expect(await screen.findByText('2 more waiting')).toBeVisible();
  });

  it('is in Portuguese when the language is', async () => {
    await open(true, 'pt-BR');
    expect(await screen.findByRole('button', { name: 'Permitir' })).toBeVisible();
    expect(screen.getByRole('radio', { name: 'Só desta vez' })).toBeChecked();
  });

  it('shows hostile names as plain text', async () => {
    const transport = await open();
    const first = (await transport.listPrompts())[0]!;
    app.prompts = [
      { ...first, destination: '<img src=x onerror=alert(1)>', exe_path: '/tmp/<b>x</b>' },
    ];
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeVisible();
    expect(document.querySelector('img')).toBeNull();
  });
});
