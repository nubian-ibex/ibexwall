import type { CheckResult } from '../gen/contracts';

/** Overview cards group related checks under one plain-language heading. */
export type CardId =
  'boot' | 'disk' | 'firewall' | 'confinement' | 'accounts' | 'ports' | 'updates';

export type CardState = 'ok' | 'attention' | 'unknown';

export interface Card {
  id: CardId;
  icon: string;
  state: CardState;
  checks: CheckResult[];
}

const GROUPS: { id: CardId; icon: string; ids: string[] }[] = [
  {
    id: 'boot',
    icon: 'lock-keyhole',
    ids: ['posture.secure_boot', 'posture.lockdown', 'posture.tpm2'],
  },
  { id: 'disk', icon: 'hard-drive', ids: ['posture.disk_encryption', 'posture.swap_encryption'] },
  { id: 'firewall', icon: 'brick-wall', ids: ['posture.firewall'] },
  {
    id: 'confinement',
    icon: 'box',
    ids: ['posture.mac', 'posture.tmp_mount', 'posture.shm_mount', 'posture.core_dumps'],
  },
  { id: 'accounts', icon: 'user-lock', ids: ['posture.sudo_nopasswd'] },
  { id: 'ports', icon: 'radio', ids: ['ports.exposed_services'] },
  {
    id: 'updates',
    icon: 'refresh-cw',
    ids: ['posture.updates_pending', 'posture.updates_automatic', 'posture.firmware_hsi'],
  },
];

export function cardState(checks: CheckResult[]): CardState {
  if (checks.some((c) => c.outcome === 'fail')) return 'attention';
  if (checks.some((c) => c.outcome === 'pass')) return 'ok';
  return 'unknown';
}

/** Cards only appear when at least one of their checks reported. */
export function cardsFrom(results: CheckResult[]): Card[] {
  const byId = new Map(results.map((r) => [r.id, r]));
  return GROUPS.flatMap(({ id, icon, ids }) => {
    const checks = ids.flatMap((checkId) => {
      const result = byId.get(checkId);
      return result ? [result] : [];
    });
    return checks.length === 0 ? [] : [{ id, icon, state: cardState(checks), checks }];
  });
}
