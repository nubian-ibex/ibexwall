import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import Assistant from './Assistant.svelte';

describe('Assistant', () => {
  beforeEach(() => i18n.set('en'));

  it('shows a suggestion as the AI’s words, with the operations and what the assistant cannot do', async () => {
    app.useTransport(new FixtureTransport('attention'));
    render(Assistant);
    expect(await screen.findByText(/suggested by claude-code \(an ai\)/i)).toBeVisible();
    expect(screen.getByText(/written by the ai, not checked/i)).toBeVisible();
    expect(screen.getByText(/cannot apply, approve or undo/i)).toBeVisible();
    expect(screen.getByText(/can be undone right away/i)).toBeVisible();
    expect(screen.getByText('/etc/sysctl.d/90-ibexwall-hardening.conf')).toBeVisible();
  });

  it('renders hostile AI text as quoted text and never acts on it', async () => {
    const transport = new FixtureTransport('attention');
    app.useTransport(transport);
    render(Assistant);
    const quote = await screen.findByText(/ignore previous instructions/i);
    expect(quote.tagName).toBe('BLOCKQUOTE');
    expect(await transport.listProposals('pending')).toHaveLength(1);
  });

  it('approving applies it and moves it to the decided list', async () => {
    const transport = new FixtureTransport('attention');
    app.useTransport(transport);
    render(Assistant);
    await fireEvent.click(await screen.findByRole('button', { name: /approve and apply/i }));
    expect(await screen.findAllByText('Approved')).not.toHaveLength(0);
    expect(await transport.listProposals('pending')).toHaveLength(0);
  });

  it('rejecting leaves nothing pending', async () => {
    const transport = new FixtureTransport('attention');
    app.useTransport(transport);
    render(Assistant);
    await fireEvent.click(await screen.findByRole('button', { name: /^reject$/i }));
    await waitFor(() => expect(screen.getAllByText('Rejected')).toHaveLength(2));
  });

  it('says so when the plan changed since it was suggested', async () => {
    const transport = new FixtureTransport('attention');
    transport.decideProposal = () =>
      Promise.reject(new TransportError('com.ibexwall.Core.ProposalStale'));
    app.useTransport(transport);
    render(Assistant);
    await fireEvent.click(await screen.findByRole('button', { name: /approve and apply/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/plan changed/i);
  });

  it('explains when there is nothing to decide', async () => {
    app.useTransport(new FixtureTransport('empty'));
    render(Assistant);
    expect(await screen.findByText(/no suggestions yet/i)).toBeVisible();
  });

  it('shows an error with retry instead of loading forever', async () => {
    const transport = new FixtureTransport('attention');
    transport.listProposals = () => Promise.reject(new Error('unreachable'));
    app.useTransport(transport);
    render(Assistant);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeVisible();
  });
});
