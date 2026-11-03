import { describe, expect, it } from 'vitest';
import type { FirewallState } from '../gen/contracts';
import {
  canEnableBasic,
  canSwitchProfile,
  format,
  hasServices,
  portSpec,
  profileOf,
  unnamedListening,
} from './firewall';

const state = (over: Partial<FirewallState>): FirewallState => ({
  backend: 'firewalld',
  active: true,
  zone: 'public',
  ports: [],
  services: [],
  listening: [],
  other: [],
  networks: [],
  ...over,
});

describe('portSpec', () => {
  it('accepts ports 1 to 65535 with a known protocol', () => {
    expect(portSpec('8080', 'tcp')).toBe('8080/tcp');
    expect(portSpec(' 53 ', 'udp')).toBe('53/udp');
    expect(portSpec('1', 'tcp')).toBe('1/tcp');
    expect(portSpec('65535', 'tcp')).toBe('65535/tcp');
  });

  it('refuses everything else, including text that looks like an option', () => {
    for (const bad of ['', '0', '65536', '-1', '8080/tcp', '80;rm', '--reload', '1e3', '٣']) {
      expect(portSpec(bad, 'tcp'), bad).toBeNull();
    }
    expect(portSpec('80', 'sctp')).toBeNull();
    expect(portSpec('80', '')).toBeNull();
  });
});

describe('state helpers', () => {
  it('lists listening ports no rule names', () => {
    const s = state({
      ports: [{ port: 22, proto: 'tcp' }],
      listening: [
        { port: 22, proto: 'tcp' },
        { port: 22, proto: 'udp' },
        { port: 631, proto: 'tcp' },
      ],
    });
    expect(unnamedListening(s).map(format)).toEqual(['22/udp', '631/tcp']);
  });

  it('knows what each manager can do', () => {
    expect(canSwitchProfile(state({}))).toBe(true);
    expect(canSwitchProfile(state({ active: false }))).toBe(false);
    expect(canSwitchProfile(state({ backend: 'ufw' }))).toBe(false);
    expect(hasServices(state({}))).toBe(true);
    expect(hasServices(state({ backend: 'ufw' }))).toBe(false);
    expect(canEnableBasic(state({ backend: 'nftables', active: false }))).toBe(true);
    expect(canEnableBasic(state({ backend: 'nftables', active: true }))).toBe(false);
    expect(canEnableBasic(state({ backend: 'ufw', active: false }))).toBe(false);
  });

  it('falls back to public for a profile it does not know', () => {
    expect(profileOf('home')).toBe('home');
    expect(profileOf('<script>')).toBe('public');
  });
});
