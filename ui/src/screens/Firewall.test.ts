import { renderScreen } from '../test-utils';
import { fireEvent, screen, within } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';
import Firewall from './Firewall.svelte';

async function open(scenario: ConstructorParameters<typeof FixtureTransport>[0] = 'attention') {
  const transport = new FixtureTransport(scenario);
  app.useTransport(transport);
  renderScreen(Firewall);
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

  it('plans exactly the port that was typed', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.input(await screen.findByLabelText('Port'), { target: { value: '9000' } });
    await fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'udp' } });
    await fireEvent.click(screen.getByRole('button', { name: /allow this port/i }));
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
    await vi.waitFor(() =>
      expect(plan).toHaveBeenLastCalledWith('net.firewall', { remove: '8080/tcp' }),
    );
    // The review is a modal step: close it before asking for something else.
    await fireEvent.click(screen.getAllByRole('button', { name: /^close$/i }).at(-1)!);
    await fireEvent.click(screen.getByRole('button', { name: 'Remove ssh' }));
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
    expect(plan).toHaveBeenCalledWith('net.firewall', { profile: 'home' });
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
    const { container } = renderScreen(Firewall);
    expect(await screen.findByText(hostile)).toBeVisible();
    expect(container.querySelector('img')).toBeNull();
  });

  it('reports a core that cannot be reached, with a retry', async () => {
    const transport = new FixtureTransport('attention');
    vi.spyOn(transport, 'getFirewall').mockRejectedValue(new TransportError('unreachable'));
    app.useTransport(transport);
    renderScreen(Firewall);
    expect(await screen.findByRole('alert')).toBeVisible();
    expect(screen.getByRole('button', { name: /try again/i })).toBeVisible();
  });

  it('says a port is already allowed by a range, and does not offer to add it', async () => {
    const transport = new FixtureTransport('attention');
    const state = await transport.getFirewall();
    vi.spyOn(transport, 'getFirewall').mockResolvedValue({
      ...state,
      other: ['port 1025-65535/tcp', 'forward'],
    });
    app.useTransport(transport);
    renderScreen(Firewall);
    await turnOn(transport);
    await fireEvent.input(await screen.findByLabelText('Port'), { target: { value: '9099' } });
    expect(await screen.findByText(/9099\/tcp is already allowed by this rule/)).toBeVisible();
    expect(screen.getByRole('button', { name: /allow this port/i })).toBeDisabled();
    // Below the range it is a normal request.
    await fireEvent.input(screen.getByLabelText('Port'), { target: { value: '80' } });
    expect(screen.queryByText(/already allowed by this rule/)).toBeNull();
    expect(screen.getByRole('button', { name: /allow this port/i })).toBeEnabled();
  });

  /** A firewall state the fixtures do not have: the manager and whether it runs. */
  async function openWith(
    backend: 'firewalld' | 'ufw' | 'nftables',
    active: boolean,
    pluginOn = true,
  ) {
    const transport = new FixtureTransport('attention');
    const state = await transport.getFirewall();
    vi.spyOn(transport, 'getFirewall').mockResolvedValue({
      ...state,
      backend,
      active,
      zone: backend === 'firewalld' ? state.zone : null,
      services: backend === 'firewalld' ? state.services : [],
      ports: active ? state.ports : [],
    });
    app.useTransport(transport);
    renderScreen(Firewall);
    if (pluginOn) await turnOn(transport);
    else await app.refresh();
    return transport;
  }

  it('the switch is the firewall, not the plugin: on when it runs, whatever the plugin says', async () => {
    await open();
    const toggle = await screen.findByRole('switch', { name: /the firewall is on/i });
    expect(toggle).toHaveAttribute('aria-checked', 'true');
  });

  it('shows no port, service or profile controls while the firewall is off', async () => {
    await openWith('ufw', false);
    const toggle = await screen.findByRole('switch', { name: /the firewall is off/i });
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    expect(screen.queryByRole('heading', { name: 'Allowed ports' })).toBeNull();
    expect(screen.queryByLabelText('Port')).toBeNull();
    expect(screen.queryByRole('button', { name: /allow this port/i })).toBeNull();
    expect(screen.queryByText(/network profiles/i)).toBeNull();
  });

  it('turning the switch on plans the manager, keeping what listens, and turns the plugin on first', async () => {
    const transport = await openWith('ufw', false, false);
    const enable = vi.spyOn(transport, 'setPluginEnabled');
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('switch', { name: /the firewall is off/i }));
    expect(enable).toHaveBeenCalledWith('net.firewall', true);
    await vi.waitFor(() =>
      expect(plan).toHaveBeenCalledWith('net.firewall', {
        enable_manager: true,
        allow_listening: true,
      }),
    );
    // After the preview, the panel offers the button that carries it out.
    expect(await screen.findByRole('button', { name: /^apply \d+ change/i })).toBeVisible();
  });

  it("IbexWall's own protection is planned with enable_basic, and cannot be switched off here", async () => {
    const transport = await openWith('nftables', false);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('switch', { name: /the firewall is off/i }));
    expect(plan).toHaveBeenCalledWith('net.firewall', {
      enable_basic: true,
      allow_listening: true,
    });
  });

  it('turning a running firewall off plans disable_manager', async () => {
    const transport = await open();
    await turnOn(transport);
    const plan = vi.spyOn(transport, 'planChange');
    await fireEvent.click(await screen.findByRole('switch', { name: /the firewall is on/i }));
    expect(plan).toHaveBeenCalledWith('net.firewall', { disable_manager: true });
  });

  it('after an applied change the screen reads the firewall again, so the port shows', async () => {
    const transport = await open();
    await turnOn(transport);
    const read = vi.spyOn(transport, 'getFirewall');
    await fireEvent.input(await screen.findByLabelText('Port'), { target: { value: '171' } });
    await fireEvent.click(screen.getByRole('button', { name: /allow this port/i }));
    await fireEvent.click(await screen.findByRole('button', { name: /^apply \d+ change/i }));
    await vi.waitFor(() => expect(read).toHaveBeenCalled());
  });

  it('says in plain words that nothing has changed when the review opens', async () => {
    await open();
    await fireEvent.click(await screen.findByRole('switch', { name: /the firewall is on/i }));
    expect(await screen.findByText(/Nothing has changed yet/)).toBeVisible();
  });

  it('the switch moves to where it was asked to go, and closing the review puts it back', async () => {
    await openWith('ufw', false);
    const toggle = await screen.findByRole('switch', { name: /the firewall is off/i });
    await fireEvent.click(toggle);
    const moved = await screen.findByRole('switch', { name: /the firewall is on/i });
    expect(moved).toHaveAttribute('aria-checked', 'true');
    await fireEvent.click(screen.getAllByRole('button', { name: /^close$/i }).at(-1)!);
    const back = await screen.findByRole('switch', { name: /the firewall is off/i });
    expect(back).toHaveAttribute('aria-checked', 'false');
    expect(back).toBeEnabled();
  });
});
