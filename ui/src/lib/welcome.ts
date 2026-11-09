/** Plugins the first run offers to turn on: they read and warn, and
 * change nothing on the machine until the person plans a change. */
export const RECOMMENDED = [
  'net.firewall',
  'vuln.cves',
  'endpoint.persistence',
  'endpoint.rootkit',
  'privacy.telemetry',
  'system.session-lock',
];

const KEY = 'ibexwall.welcome-done';

/** Whether the first run still has to be shown on this account. */
export function needsWelcome(): boolean {
  try {
    return localStorage.getItem(KEY) === null;
  } catch {
    return false;
  }
}

export function finishWelcome() {
  try {
    localStorage.setItem(KEY, '1');
  } catch {
    // Without storage the welcome shows again next time; nothing breaks.
  }
}
