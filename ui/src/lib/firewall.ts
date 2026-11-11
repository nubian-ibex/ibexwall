// Helpers for the Firewall screen. The strings they receive (service and
// network names, rules read from configuration files) are untrusted
// display text.
import type { FirewallPort, FirewallState } from '../gen/contracts';

export const PROFILES = ['home', 'work', 'public', 'travel'] as const;
export type ProfileId = (typeof PROFILES)[number];

export const PROTOCOLS = ['tcp', 'udp'] as const;
export type ProtocolId = (typeof PROTOCOLS)[number];

/** `8080/tcp`, the form the firewall plugin takes; `null` when invalid. */
export function portSpec(port: string, proto: string): string | null {
  const text = port.trim();
  if (!/^\d{1,5}$/.test(text)) return null;
  const number = Number(text);
  if (number < 1 || number > 65535) return null;
  if (!(PROTOCOLS as readonly string[]).includes(proto)) return null;
  return `${number}/${proto}`;
}

export function format(port: FirewallPort): string {
  return `${port.port}/${port.proto}`;
}

/** Ports with a socket on every address that no rule names: the
 *  firewall may be keeping them closed (services are named, not
 *  numbered, so this says "no port rule", not "blocked"). */
export function unnamedListening(state: FirewallState): FirewallPort[] {
  const allowed = new Set(state.ports.map(format));
  return state.listening.filter((port) => !allowed.has(format(port)));
}

/** Only firewalld has zones to switch between. */
export function canSwitchProfile(state: FirewallState): boolean {
  return state.backend === 'firewalld' && state.active === true;
}

/** Whether services (named bundles of ports) can be allowed. */
export function hasServices(state: FirewallState): boolean {
  return state.backend === 'firewalld';
}

/** A known profile id, or `public` for anything unexpected. */
export function profileOf(name: string): ProfileId {
  return (PROFILES as readonly string[]).includes(name) ? (name as ProfileId) : 'public';
}

/** Turning on IbexWall's own protection: only when nothing else manages it. */
export function canEnableBasic(state: FirewallState): boolean {
  return state.backend === 'nftables' && state.active !== true;
}

/** The rule, as the firewall shows it, that already lets `port/proto` in
 * through a range (Fedora Workstation allows 1025-65535, for one). Mirrors
 * the plugin, which refuses to add a port such a rule covers. */
export function coveringRange(state: FirewallState, spec: string): string | null {
  const [portText, proto] = spec.split('/');
  const port = Number(portText);
  const inRange = (range: string, separator: string) => {
    const [low, high] = range.split(separator).map(Number);
    return low !== undefined && high !== undefined && port >= low && port <= high;
  };
  const protoOk = (text: string | undefined) => text === proto || text === 'any';
  for (const rule of state.other) {
    if (rule.startsWith('port ')) {
      const [range, ruleProto] = rule.slice(5).split('/');
      if (range && range.includes('-') && protoOk(ruleProto) && inRange(range, '-')) return rule;
      continue;
    }
    // A plain ufw tuple: action proto dport dst sport src direction
    const fields = rule.split(/\s+/);
    const [action, ruleProto, dport, dst, sport, src, direction] = fields;
    const open = (net: string | undefined) => net === '0.0.0.0/0' || net === '::/0';
    if (
      action === 'allow' &&
      direction === 'in' &&
      sport === 'any' &&
      open(dst) &&
      open(src) &&
      dport &&
      dport.includes(':') &&
      protoOk(ruleProto) &&
      inRange(dport, ':')
    ) {
      return rule;
    }
  }
  return null;
}

/** firewalld or ufw is installed but off: IbexWall can turn it on (ADR-0046). */
export function canTurnOnManager(state: FirewallState): boolean {
  return (state.backend === 'firewalld' || state.backend === 'ufw') && state.active === false;
}
