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
