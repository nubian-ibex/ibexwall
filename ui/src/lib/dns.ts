// The choices the DNS screen offers. The source of truth is the net.dns
// plugin (plugins/net.dns/src/presets.rs and the list presets of
// ibexwall-dns); a Rust test fails when this file drifts from them.
export const DNS_PROVIDERS = [
  { id: 'quad9', jurisdiction: 'CH', transports: ['tls', 'https', 'h3', 'quic'] },
  { id: 'cloudflare', jurisdiction: 'US', transports: ['tls', 'https', 'h3'] },
  { id: 'adguard', jurisdiction: 'CY', transports: ['tls', 'https', 'h3', 'quic'] },
  { id: 'dns4eu', jurisdiction: 'CZ', transports: ['tls', 'https'] },
] as const;

export const DNS_LISTS = [
  'hagezi-light',
  'hagezi-normal',
  'hagezi-pro',
  'hagezi-pro-plus',
  'hagezi-ultimate',
  'oisd-small',
  'oisd-big',
  'stevenblack',
] as const;

export type DnsProviderId = (typeof DNS_PROVIDERS)[number]['id'];
export type DnsTransport = 'tls' | 'https' | 'h3' | 'quic';

export interface DnsChoice {
  provider: DnsProviderId;
  transport: DnsTransport;
  list: 'none' | (typeof DNS_LISTS)[number];
  enforcement: boolean;
  blockDoh: boolean;
  /** Explicit consent: set each installed browser's own DoH policy off. */
  browserPolicies: boolean;
}

export const DNS_DEFAULTS: DnsChoice = {
  provider: 'quad9',
  transport: 'tls',
  list: 'none',
  enforcement: true,
  blockDoh: true,
  browserPolicies: false,
};

/** The patch the net.dns plugin plans from. */
export function dnsPatch(choice: DnsChoice): Record<string, unknown> {
  return {
    provider: choice.provider,
    transport: choice.transport,
    lists: choice.list === 'none' ? [] : [{ id: choice.list }],
    enforcement: choice.enforcement,
    block_doh: choice.blockDoh,
    browser_policies: choice.browserPolicies,
  };
}

/** Keeps the transport valid when the provider changes. */
export function transportFor(provider: DnsProviderId, wanted: DnsTransport): DnsTransport {
  const found = DNS_PROVIDERS.find((p) => p.id === provider);
  return found && (found.transports as readonly string[]).includes(wanted) ? wanted : 'tls';
}
