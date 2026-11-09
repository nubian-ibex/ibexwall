import { describe, expect, it } from 'vitest';
import {
  choiceFromConfig,
  DNS_DEFAULTS,
  dnsPatch,
  isLocalAddress,
  ownProblems,
  OWN_DEFAULTS,
} from './dns';

const own = (extra: Partial<typeof OWN_DEFAULTS>) => ({ ...OWN_DEFAULTS, enabled: true, ...extra });

describe('own DNS servers', () => {
  it('knows which addresses never leave the local network', () => {
    for (const a of [
      '192.168.1.1',
      '10.0.0.2',
      '172.20.0.1',
      '100.64.0.9',
      '127.0.0.1',
      'fd00::1',
      'fe80::1',
    ])
      expect(isLocalAddress(a), a).toBe(true);
    for (const a of [
      '8.8.8.8',
      '1.1.1.1',
      '172.32.0.1',
      '100.128.0.1',
      '2001:4860:4860::8888',
      'x',
    ])
      expect(isLocalAddress(a), a).toBe(false);
  });

  it('refuses unencrypted DNS to a public address and asks for the name when encrypted', () => {
    expect(ownProblems(own({ primary: '8.8.8.8' }))).toContain('dns-own-problem-public-plain');
    expect(ownProblems(own({ primary: '9.9.9.9', primaryTransport: 'tls' }))).toContain(
      'dns-own-problem-name',
    );
    expect(
      ownProblems(
        own({ primary: '9.9.9.9', primaryTransport: 'tls', serverName: 'dns.quad9.net' }),
      ),
    ).toEqual([]);
    expect(ownProblems(own({}))).toContain('dns-own-problem-primary');
    expect(ownProblems({ ...OWN_DEFAULTS })).toEqual([]);
  });

  it('builds the failover order and the split-DNS route into the plugin patch', () => {
    const patch = dnsPatch({
      ...DNS_DEFAULTS,
      own: own({
        primary: '10.0.0.2',
        secondary: '9.9.9.9',
        secondaryTransport: 'tls',
        serverName: 'dns.quad9.net',
        domains: 'Corp.Example, internal',
        routeServer: '10.0.0.2',
      }),
    });
    expect(patch.servers).toEqual([
      { ip: '10.0.0.2', transport: 'plain' },
      { ip: '9.9.9.9', transport: 'tls', server_name: 'dns.quad9.net' },
    ]);
    expect(patch.routes).toEqual([
      { domains: ['corp.example', 'internal'], servers: [{ ip: '10.0.0.2', transport: 'plain' }] },
    ]);
  });

  it('sends no custom servers when they are off or wrong', () => {
    expect(dnsPatch(DNS_DEFAULTS).servers).toBeUndefined();
    expect(dnsPatch({ ...DNS_DEFAULTS, own: own({ primary: '8.8.8.8' }) }).servers).toBeUndefined();
  });
});

describe('choiceFromConfig', () => {
  it('shows what is applied, not the defaults', () => {
    const choice = choiceFromConfig({
      provider: 'adguard',
      transport: 'https',
      lists: [{ id: 'hagezi-pro' }],
      enforcement: false,
      block_doh: false,
    });
    expect(choice.provider).toBe('adguard');
    expect(choice.transport).toBe('https');
    expect(choice.list).toBe('hagezi-pro');
    expect(choice.enforcement).toBe(false);
    expect(choice.blockDoh).toBe(false);
    expect(choice.own.enabled).toBe(false);
  });

  it('reads own servers and keeps the defaults for what is unknown', () => {
    const choice = choiceFromConfig({
      provider: 'not-a-provider',
      servers: [
        { ip: '192.168.1.1', transport: 'plain' },
        { ip: '9.9.9.9', transport: 'tls', server_name: 'dns.quad9.net' },
      ],
    });
    expect(choice.provider).toBe(DNS_DEFAULTS.provider);
    expect(choice.own).toMatchObject({
      enabled: true,
      primary: '192.168.1.1',
      primaryTransport: 'plain',
      secondary: '9.9.9.9',
      secondaryTransport: 'tls',
    });
  });
});
