// The UI talks to the core through this interface. The desktop app
// implements it with Tauri commands (varlink on the Rust side); tests and
// design work use the fixture implementation.
import type {
  Finding,
  HistoryEntry,
  Info,
  Plan,
  PluginInfo,
  Posture,
  Transaction,
} from '../gen/contracts';

/** A named varlink error, e.g. `com.ibexwall.Core.PermissionDenied`. */
export class TransportError extends Error {
  constructor(
    readonly code: string,
    readonly parameters: Record<string, unknown> = {},
  ) {
    super(code);
    this.name = 'TransportError';
  }

  get kind(): 'denied' | 'locked' | 'unreachable' | 'other' {
    if (this.code.endsWith('.PermissionDenied')) return 'denied';
    if (this.code.endsWith('.Locked')) return 'locked';
    if (this.code === 'unreachable') return 'unreachable';
    return 'other';
  }
}

export interface Transport {
  getInfo(): Promise<Info>;
  getPosture(): Promise<Posture>;
  listPlugins(): Promise<PluginInfo[]>;
  listFindings(plugin?: string): Promise<Finding[]>;
  runChecks(plugin?: string): Promise<Finding[]>;
  setPluginEnabled(id: string, enabled: boolean): Promise<void>;
  planChange(plugin: string, patch: Record<string, unknown>): Promise<Plan>;
  apply(planId: string, confirmTimeoutSeconds?: number): Promise<Transaction>;
  confirm(transactionId: string): Promise<void>;
  rollback(target: string): Promise<Transaction>;
  history(limit?: number): Promise<HistoryEntry[]>;
}
