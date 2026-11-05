import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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

describe('Assistant: connect an AI', () => {
  beforeEach(() => i18n.set('en'));

  async function open(transport = new FixtureTransport('attention')) {
    app.useTransport(transport);
    render(Assistant);
    await screen.findByRole('heading', { name: /connect an ai|conectar uma ia/i });
    return transport;
  }

  it('shows what to paste for the chosen program and changes with it', async () => {
    await open();
    expect(screen.getByText(/\.mcp\.json/)).toBeVisible();
    expect(screen.getByText(/"command": "ibexwall-mcp"/)).toBeVisible();
    await fireEvent.change(screen.getByLabelText(/^program$/i), { target: { value: 'opencode' } });
    expect(screen.getByText(/opencode\.json/)).toBeVisible();
    expect(screen.getByText(/"type": "local"/)).toBeVisible();
  });

  it('offers three presets only, and plans exactly the chosen one', async () => {
    const transport = new FixtureTransport('attention');
    const plan = vi.spyOn(transport, 'planChange');
    await open(transport);
    const select = screen.getAllByLabelText(/^allowed$/i)[0] as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(['read', 'plan', 'propose']);
    await fireEvent.change(select, { target: { value: 'propose' } });
    expect(screen.getByText(/leave a suggestion here/i)).toBeVisible();
    await fireEvent.click(screen.getAllByRole('button', { name: /simulate/i })[0]!);
    expect(plan).toHaveBeenCalledWith('system.assistant', {
      action: 'client',
      client: 'claude-code',
      preset: 'propose',
    });
  });

  it('makes a key once, sends the plan only its hash, and lists the existing keys', async () => {
    const transport = new FixtureTransport('attention');
    const plan = vi.spyOn(transport, 'planChange');
    await open(transport);
    expect(await screen.findByText('work laptop')).toBeVisible();
    expect(screen.getByText(/on, listening at 127\.0\.0\.1:8765/i)).toBeVisible();
    await fireEvent.input(screen.getByLabelText(/what it is for/i), { target: { value: 'desk' } });
    await fireEvent.click(screen.getByRole('button', { name: /make the key/i }));
    expect(await screen.findByText(/copy this key now/i)).toBeVisible();
    expect(screen.getByText(/ibx_fix01_/)).toBeVisible();
    await fireEvent.click(screen.getAllByRole('button', { name: /simulate/i }).at(-1)!);
    const patch = plan.mock.calls.at(-1)![1] as Record<string, string>;
    expect(patch['action']).toBe('token_add');
    expect(patch['hash']).toMatch(/^\$argon2id\$/);
    expect(JSON.stringify(patch)).not.toContain('AbCdEfGhIj');
  });

  it('removes a key through a reviewed change', async () => {
    const transport = new FixtureTransport('attention');
    const plan = vi.spyOn(transport, 'planChange');
    await open(transport);
    await fireEvent.click(await screen.findByRole('button', { name: /^remove$/i }));
    await fireEvent.click(screen.getAllByRole('button', { name: /simulate/i }).at(-1)!);
    expect(plan).toHaveBeenLastCalledWith('system.assistant', {
      action: 'token_revoke',
      id: 'k1x',
    });
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    await open();
    expect(screen.getAllByText(/conectar uma ia/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/acessar o ibexwall de outro computador/i)).toBeVisible();
  });
});
