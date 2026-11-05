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

/** Servers of your own: a router, a corporate resolver, a VPN's DNS. */
export interface OwnDns {
  enabled: boolean;
  primary: string;
  /** Takes over when the primary does not answer. */
  secondary: string;
  /** `plain` is only for local-network addresses; `tls` needs the name. */
  primaryTransport: 'plain' | 'tls';
  secondaryTransport: 'plain' | 'tls';
  /** The certificate name, for a server reached over TLS. */
  serverName: string;
  /** Internal domains answered by `routeServer` (split DNS), comma separated. */
  domains: string;
  routeServer: string;
}

export const OWN_DEFAULTS: OwnDns = {
  enabled: false,
  primary: '',
  secondary: '',
  primaryTransport: 'plain',
  secondaryTransport: 'tls',
  serverName: '',
  domains: '',
  routeServer: '',
};

/** Private, loopback, link-local, unique-local and CGNAT (VPN) addresses. */
export function isLocalAddress(text: string): boolean {
  const v4 = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const parts = v4.slice(1).map(Number);
    if (parts.some((n) => n > 255)) return false;
    const a = parts[0] ?? 0;
    const b = parts[1] ?? 0;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (text.includes(':') && /^[0-9a-f:]+$/i.test(text)) {
    const first = parseInt(text.split(':')[0] || '0', 16);
    return text === '::1' || (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }
  return false;
}

export function isAddress(text: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(text) || (text.includes(':') && /^[0-9a-f:]+$/i.test(text));
}

export function isDomain(text: string): boolean {
  const name = text.replace(/\.$/, '');
  return (
    name.length > 0 &&
    name.length <= 253 &&
    name.split('.').every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  );
}

/** What is wrong with the person's own servers, as message keys (empty: fine). */
export function ownProblems(own: OwnDns): string[] {
  if (!own.enabled) return [];
  const problems: string[] = [];
  const check = (address: string, transport: 'plain' | 'tls', required: boolean) => {
    if (!address) {
      if (required) problems.push('dns-own-problem-primary');
      return;
    }
    if (!isAddress(address)) problems.push('dns-own-problem-address');
    else if (transport === 'plain' && !isLocalAddress(address))
      problems.push('dns-own-problem-public-plain');
    else if (transport === 'tls' && !isDomain(own.serverName))
      problems.push('dns-own-problem-name');
  };
  check(own.primary, own.primaryTransport, true);
  check(own.secondary, own.secondaryTransport, false);
  const domains = splitDomains(own.domains);
  if (domains.some((d) => !isDomain(d))) problems.push('dns-own-problem-domain');
  if (domains.length > 0 && !own.routeServer) problems.push('dns-own-problem-route');
  if (own.routeServer && (!isAddress(own.routeServer) || !isLocalAddress(own.routeServer)))
    problems.push('dns-own-problem-route-server');
  return [...new Set(problems)];
}

export function splitDomains(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

export interface DnsChoice {
  provider: DnsProviderId;
  transport: DnsTransport;
  list: 'none' | (typeof DNS_LISTS)[number];
  enforcement: boolean;
  blockDoh: boolean;
  /** Explicit consent: set each installed browser's own DoH policy off. */
  browserPolicies: boolean;
  own: OwnDns;
}

export const DNS_DEFAULTS: DnsChoice = {
  provider: 'quad9',
  transport: 'tls',
  list: 'none',
  enforcement: true,
  blockDoh: true,
  browserPolicies: false,
  own: { ...OWN_DEFAULTS },
};

/** The patch the net.dns plugin plans from. */
export function dnsPatch(choice: DnsChoice): Record<string, unknown> {
  const own = ownPatch(choice.own);
  return {
    ...own,
    provider: choice.provider,
    transport: choice.transport,
    lists: choice.list === 'none' ? [] : [{ id: choice.list }],
    enforcement: choice.enforcement,
    block_doh: choice.blockDoh,
    browser_policies: choice.browserPolicies,
  };
}

function ownPatch(own: OwnDns): Record<string, unknown> {
  if (!own.enabled || ownProblems(own).length > 0) return {};
  const server = (ip: string, transport: 'plain' | 'tls') =>
    transport === 'plain'
      ? { ip, transport: 'plain' }
      : { ip, transport: 'tls', server_name: own.serverName };
  const servers = [server(own.primary, own.primaryTransport)];
  if (own.secondary) servers.push(server(own.secondary, own.secondaryTransport));
  const domains = splitDomains(own.domains);
  const patch: Record<string, unknown> = { servers };
  if (domains.length > 0) {
    patch.routes = [{ domains, servers: [{ ip: own.routeServer, transport: 'plain' }] }];
  }
  return patch;
}

/** Keeps the transport valid when the provider changes. */
export function transportFor(provider: DnsProviderId, wanted: DnsTransport): DnsTransport {
  const found = DNS_PROVIDERS.find((p) => p.id === provider);
  return found && (found.transports as readonly string[]).includes(wanted) ? wanted : 'tls';
}
