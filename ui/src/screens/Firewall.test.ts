import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import Firewall from './Firewall.svelte';

async function open(scenario: ConstructorParameters<typeof FixtureTransport>[0] = 'attention') {
  const transport = new FixtureTransport(scenario);
  app.useTransport(transport);
  render(Firewall);
  await app.refresh();
  return transport;
}

/** The firewall plugin is off in the fixtures; the controls need it on. */
async function turnOn(transport: FixtureTransport) {
  const plugins = await transport.listPlugins();
  vi.spyOn(transport, 'listPlugins').mockResolvedValue(
    plugins.map((p) => (p.id === 'net.firewall' ? { ...p, enabled: true } : p)),
  );
  await app.refresh();
}

describe('Firewall screen', () => {
  beforeEach(() => i18n.set('en'));

  it('shows who manages the firewall, its zone and what it allows', async () => {
    await open();
    expect(await screen.findByRole('heading', { name: 'The firewall is on' })).toBeVisible();
    expect(screen.getByText(/Managed by firewalld/)).toBeVisible();
    expect(screen.getByText(/Zone: public/)).toBeVisible();
    expect(screen.getByText('8080/tcp')).toBeVisible();
    expect(screen.getByText('ssh')).toBeVisible();
    expect(screen.getByText(/rich rule/)).toBeVisible();
  });

  it('keeps the controls off until the plugin is on, but still shows the state', async () => {
    await open();
    expect(await screen.findByText('The firewall controls are off')).toBeVisible();
    expect(screen.getByRole('button', { name: /allow this port/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Remove 8080/tcp' })).toBeDisabled();
  });

  it('plans exactly the port that was typed', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.input(await screen.findByLabelText('Port'), { target: { value: '9000' } });
    await fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'udp' } });
    await fireEvent.click(screen.getByRole('button', { name: /allow this port/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenCalledWith('net.firewall', { allow: '9000/udp' });
  });

  it('refuses a bad port before asking the core anything', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.input(await screen.findByLabelText('Port'), { target: { value: '--reload' } });
    await fireEvent.click(screen.getByRole('button', { name: /allow this port/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('between 1 and 65535');
    expect(screen.getByLabelText('Port')).toHaveAttribute('aria-invalid', 'true');
    expect(plan).not.toHaveBeenCalled();
  });

  it('removes a port or a service through the same reviewed flow', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('button', { name: 'Remove 8080/tcp' }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenLastCalledWith('net.firewall', { remove: '8080/tcp' });
    await fireEvent.click(screen.getByRole('button', { name: 'Remove ssh' }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenLastCalledWith('net.firewall', { remove_service: 'ssh' });
  });

  it('suggests a profile for each network and warns about an open one', async () => {
    await open();
    const office = await screen.findByText('Office LAN');
    expect(office).toBeVisible();
    expect(screen.getByText('Cafe WiFi')).toBeVisible();
    expect(screen.getByText(/this network is open/i)).toBeVisible();
    expect(screen.getAllByText(/Suggested profile: Travel/).length).toBe(1);
    expect(screen.getAllByText(/Suggested profile: Public/).length).toBe(1);
  });

  it('switches profile with firewalld and says when profiles are not available', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('radio', { name: /home/i }));
    await fireEvent.click(screen.getByRole('button', { name: /switch to home/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenCalledWith('net.firewall', { profile: 'home' });
  });

  it('offers IbexWall protection only when nothing else manages the firewall', async () => {
    const transport = await open('empty');
    await turnOn(transport);
    expect(await screen.findByRole('heading', { name: 'The firewall is off' })).toBeVisible();
    expect(screen.getByText(/Profiles need firewalld/)).toBeVisible();
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(screen.getByRole('button', { name: /turn on basic protection/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /simulate/i }));
    expect(plan).toHaveBeenCalledWith('net.firewall', {
      enable_basic: true,
      allow_listening: true,
    });
  });

  it('renders in Portuguese', async () => {
    i18n.set('pt-BR');
    await open();
    expect(await screen.findByRole('heading', { name: 'O firewall está ligado' })).toBeVisible();
    expect(screen.getByText(/Esta rede é aberta/)).toBeVisible();
    const ports = screen.getByRole('region', { name: 'Portas permitidas' });
    expect(within(ports).getByText('8080/tcp')).toBeVisible();
  });

  it('shows rule text as plain text, whatever it contains', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const transport = new FixtureTransport('attention');
    const real = await transport.getFirewall();
    vi.spyOn(transport, 'getFirewall').mockResolvedValue({ ...real, other: [hostile] });
    app.useTransport(transport);
    const { container } = render(Firewall);
    expect(await screen.findByText(hostile)).toBeVisible();
    expect(container.querySelector('img')).toBeNull();
  });

  it('reports a core that cannot be reached, with a retry', async () => {
    const transport = new FixtureTransport('attention');
    vi.spyOn(transport, 'getFirewall').mockRejectedValue(new TransportError('unreachable'));
    app.useTransport(transport);
    render(Firewall);
    expect(await screen.findByRole('alert')).toBeVisible();
    expect(screen.getByRole('button', { name: /try again/i })).toBeVisible();
  });
});
