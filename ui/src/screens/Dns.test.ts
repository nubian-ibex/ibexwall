import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { DNS_DEFAULTS, DNS_PROVIDERS, dnsPatch, transportFor } from '../lib/dns';
import { FixtureTransport } from '../lib/fixtures';
import { TransportError } from '../lib/transport';
import { i18n } from '../lib/i18n.svelte';
import Dns from './Dns.svelte';

describe('Dns screen', () => {
  beforeEach(() => i18n.set('en'));

  it('shows the plugin as off with the providers and what each one logs', async () => {
    app.useTransport(new FixtureTransport('attention'));
    render(Dns);
    await app.refresh();
    expect(await screen.findByRole('heading', { name: /secure dns is off/i })).toBeVisible();
    expect(screen.getByRole('radio', { name: /quad9/i })).toBeChecked();
    expect(screen.getByText(/does not record user ip addresses/i)).toBeVisible();
    expect(screen.getByText(/deletes them within 25 hours/i)).toBeVisible();
    expect(screen.getByRole('switch', { name: /off/i })).toBeVisible();
  });

  it('sends exactly the chosen settings when simulating', async () => {
    const transport = new FixtureTransport('attention');
    const plan = vi.spyOn(transport, 'planChange');
    app.useTransport(transport);
    render(Dns);
    await app.refresh();
    await fireEvent.click(await screen.findByRole('radio', { name: /cloudflare/i }));
    await fireEvent.change(screen.getByLabelText(/how lookups are encrypted/i), {
      target: { value: 'https' },
    });
    await fireEvent.change(screen.getByLabelText(/block list/i), {
      target: { value: 'hagezi-pro' },
    });
    await fireEvent.click(screen.getByRole('checkbox', { name: /refuse unencrypted dns/i }));
    await fireEvent.click(screen.getByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenCalledWith('net.dns', {
      provider: 'cloudflare',
      transport: 'https',
      lists: [{ id: 'hagezi-pro' }],
      enforcement: false,
      block_doh: true,
      browser_policies: false,
    });
    expect(await screen.findByText('/etc/sysctl.d/90-ibexwall.conf')).toBeVisible();
  });

  it('offers only the transports a provider documents', async () => {
    app.useTransport(new FixtureTransport('attention'));
    render(Dns);
    await app.refresh();
    const select = (await screen.findByLabelText(
      /how lookups are encrypted/i,
    )) as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toContain('quic');
    await fireEvent.click(screen.getByRole('radio', { name: /cloudflare/i }));
    expect([...select.options].map((o) => o.value)).not.toContain('quic');
  });

  it('shows the reason when the plan is refused and changes nothing', async () => {
    const transport = new FixtureTransport('attention');
    transport.planChange = () =>
      Promise.reject(
        new TransportError('com.ibexwall.Core.InvalidArgument', {
          field: 'backend',
          reason: 'NetworkManager without systemd-resolved is not supported yet',
        }),
      );
    app.useTransport(transport);
    render(Dns);
    await app.refresh();
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('could not proceed');
    expect(alert).toHaveTextContent('backend');
    expect(alert).toHaveTextContent('not supported yet');
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    app.useTransport(new FixtureTransport('attention'));
    render(Dns);
    await app.refresh();
    expect(
      await screen.findByRole('heading', { name: /dns seguro está desligado/i }),
    ).toBeVisible();
    expect(screen.getByText(/não registra o endereço ip dos usuários/i)).toBeVisible();
  });
});

describe('dns choices', () => {
  it('builds the patch the plugin expects and keeps the transport valid', () => {
    expect(dnsPatch(DNS_DEFAULTS)).toEqual({
      provider: 'quad9',
      transport: 'tls',
      lists: [],
      enforcement: true,
      block_doh: true,
      browser_policies: false,
    });
    expect(dnsPatch({ ...DNS_DEFAULTS, browserPolicies: true }).browser_policies).toBe(true);
    expect(transportFor('cloudflare', 'quic')).toBe('tls');
    expect(transportFor('quad9', 'quic')).toBe('quic');
    expect(DNS_PROVIDERS.every((p) => p.transports.includes('tls'))).toBe(true);
  });
});
