// Fixture transport: the core simulated, per the spec's testing strategy.
// Scenarios mirror real situations; the "attention" data comes from the
// Fedora cloud-image fixtures collected for the check plugins.
import type {
  CheckResult,
  Finding,
  HistoryEntry,
  Info,
  Plan,
  PluginInfo,
  Posture,
  Transaction,
} from '../gen/contracts';
import { TransportError, type Transport } from './transport';

export type Scenario = 'attention' | 'protected' | 'empty' | 'error' | 'denied';

const r = (id: string, severity: CheckResult['severity'], outcome: CheckResult['outcome']) =>
  ({ id, severity, outcome }) satisfies CheckResult;

const ATTENTION: CheckResult[] = [
  r('posture.secure_boot', 'medium', 'not_applicable'),
  r('posture.lockdown', 'low', 'fail'),
  r('posture.tpm2', 'info', 'not_applicable'),
  r('posture.disk_encryption', 'high', 'fail'),
  r('posture.swap_encryption', 'medium', 'pass'),
  r('posture.mac', 'medium', 'pass'),
  r('posture.firewall', 'high', 'fail'),
  r('posture.tmp_mount', 'low', 'pass'),
  r('posture.shm_mount', 'low', 'pass'),
  r('posture.core_dumps', 'low', 'pass'),
  r('posture.sudo_nopasswd', 'medium', 'fail'),
  r('posture.updates_pending', 'high', 'not_assessed'),
  r('posture.updates_automatic', 'medium', 'not_assessed'),
  r('posture.firmware_hsi', 'low', 'not_assessed'),
  r('ports.exposed_services', 'medium', 'fail'),
];

const PROTECTED: CheckResult[] = ATTENTION.map((c) =>
  c.outcome === 'fail' ? { ...c, outcome: 'pass' as const } : c,
);

function score(results: CheckResult[]): number | null {
  const weight = { critical: 10, high: 6, medium: 3, low: 1, info: 0 } as const;
  let passed = 0;
  let total = 0;
  for (const c of results) {
    if (c.outcome === 'pass') passed += weight[c.severity];
    if (c.outcome === 'pass' || c.outcome === 'fail') total += weight[c.severity];
  }
  return total === 0 ? null : Math.round((passed * 100) / total);
}

const finding = (
  id: string,
  plugin: string,
  severity: Finding['severity'],
  key: string,
  args: Record<string, string> = {},
): Finding => ({
  id,
  plugin,
  severity,
  title_key: `${key}-title`,
  summary_key: `${key}-summary`,
  args,
  references: [],
  status: 'open',
  detected_at: '2026-11-01T12:00:00Z',
});

const FINDINGS: Finding[] = [
  finding('posture.disk_encryption', 'system.posture', 'high', 'posture-disk-encryption'),
  finding('posture.firewall', 'system.posture', 'high', 'posture-firewall'),
  finding('posture.sudo_nopasswd', 'system.posture', 'medium', 'posture-sudo-nopasswd'),
  finding('posture.lockdown', 'system.posture', 'low', 'posture-lockdown'),
  finding('ports.tcp.22', 'system.ports', 'medium', 'ports-exposed', {
    port: '22',
    proto: 'TCP',
    process: 'sshd',
  }),
];

const PLUGINS: PluginInfo[] = [
  {
    id: 'system.posture',
    name: 'System posture',
    version: '0.1.0',
    kinds: ['check'],
    enabled: true,
    origin: 'official',
    status: 'ok',
    compatible: true,
    conflicts: [],
    locked: false,
  },
  {
    id: 'system.ports',
    name: 'Exposed ports',
    version: '0.1.0',
    kinds: ['check'],
    enabled: true,
    origin: 'official',
    status: 'ok',
    compatible: true,
    conflicts: [],
    locked: false,
  },
];

const INFO: Info = {
  version: '0.1.0',
  api: 1,
  distro: 'fedora',
  kernel: '6.19.10',
  features: [],
  degraded: [],
};

export class FixtureTransport implements Transport {
  constructor(
    readonly scenario: Scenario = 'attention',
    private readonly latencyMs = 0,
  ) {}

  private async gate<T>(value: () => T): Promise<T> {
    if (this.latencyMs > 0) await new Promise((done) => setTimeout(done, this.latencyMs));
    if (this.scenario === 'error') throw new TransportError('unreachable');
    if (this.scenario === 'denied') {
      throw new TransportError('com.ibexwall.Core.PermissionDenied', {
        action: 'com.ibexwall.read',
      });
    }
    return value();
  }

  private results(): CheckResult[] {
    switch (this.scenario) {
      case 'protected':
        return PROTECTED;
      case 'empty':
        return [];
      default:
        return ATTENTION;
    }
  }

  getInfo() {
    return this.gate(() => INFO);
  }

  getPosture() {
    return this.gate((): Posture => {
      const results = this.results();
      return {
        score: score(results),
        generated_at: '2026-11-01T12:00:00Z',
        protections: [],
        open_findings: results.filter((c) => c.outcome === 'fail').length,
        results,
      };
    });
  }

  listPlugins() {
    return this.gate(() => PLUGINS);
  }

  listFindings(plugin?: string) {
    return this.gate(() => {
      if (this.scenario === 'empty' || this.scenario === 'protected') return [];
      return plugin ? FINDINGS.filter((f) => f.plugin === plugin) : FINDINGS;
    });
  }

  runChecks(plugin?: string) {
    return this.listFindings(plugin);
  }

  setPluginEnabled() {
    return this.gate(() => undefined);
  }

  planChange(plugin: string) {
    return this.gate((): Plan => ({
      id: 'plan-fixture-1',
      plugin,
      ops: [
        {
          op: 'file.write',
          target: '/etc/sysctl.d/90-ibexwall.conf',
          diff: '+kernel.kptr_restrict = 2',
          risk: [],
        },
      ],
      risk: this.scenario === 'attention' ? ['network'] : [],
      reversible: 'immediate',
      may_affect_keys: this.scenario === 'attention' ? ['posture-may-affect-example'] : [],
      requires_confirm: this.scenario === 'attention',
      expires_at: '2026-11-01T12:10:00Z',
    }));
  }

  apply(planId: string) {
    return this.gate((): Transaction => ({
      id: 'tx-fixture-1',
      plan_id: planId,
      state: this.scenario === 'attention' ? 'pending_confirm' : 'committed',
      started_at: '2026-11-01T12:00:00Z',
      confirm_deadline: this.scenario === 'attention' ? '2026-11-01T12:01:00Z' : undefined,
      restore_point: 'snapshots/tx-fixture-1',
    }));
  }

  confirm() {
    return this.gate(() => undefined);
  }

  rollback(target: string) {
    return this.gate((): Transaction => ({
      id: target,
      plan_id: 'plan-fixture-1',
      state: 'rolled_back',
      started_at: '2026-11-01T12:00:00Z',
      restore_point: `snapshots/${target}`,
    }));
  }

  history() {
    return this.gate((): HistoryEntry[] => {
      if (this.scenario === 'empty') return [];
      return [
        {
          seq: 2,
          ts: '2026-11-01T11:58:00Z',
          actor: 'user:1000',
          plugin: 'system.posture',
          transaction: 'tx-fixture-1',
          result: 'committed',
        },
        {
          seq: 1,
          ts: '2026-11-01T11:30:00Z',
          actor: 'system',
          plugin: 'system.ports',
          transaction: 'tx-fixture-0',
          result: 'rolled_back',
        },
      ];
    });
  }

  getManifest(id: string): Promise<Record<string, unknown>> {
    return this.gate((): Record<string, unknown> => ({
      id,
      privileges: {
        write_paths: id === 'system.posture' ? [] : ['/etc/sysctl.d'],
        units: id === 'system.posture' ? [] : ['chronyd.service'],
        sysctl_keys: id === 'system.posture' ? [] : ['kernel.kptr_restrict'],
        exec: [],
        nft_prefix: null,
      },
    }));
  }
}
