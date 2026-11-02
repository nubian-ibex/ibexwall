// Transport backed by the Tauri commands (the Rust side is a varlink
// client). Errors arrive as { code, parameters } and become TransportError.
import type {
  Finding,
  HistoryEntry,
  Info,
  Plan,
  PluginInfo,
  Posture,
  Transaction,
} from '../gen/contracts';
import { TransportError, type Transport } from './transport';

/// True when running inside the Tauri shell.
export function insideTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

interface InvokeError {
  code: string;
  parameters?: Record<string, unknown>;
}

async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return (await invoke(command, args)) as T;
  } catch (error) {
    const shaped = error as Partial<InvokeError>;
    if (shaped && typeof shaped.code === 'string') {
      throw new TransportError(shaped.code, shaped.parameters ?? {});
    }
    throw new TransportError('unreachable');
  }
}

/** The varlink reply wraps the payload; the commands return it directly. */
async function unwrapped<T>(
  command: string,
  key: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const reply = await invoke<Record<string, unknown>>(command, args);
  return reply[key] as T;
}

export class TauriTransport implements Transport {
  getInfo() {
    return unwrapped<Info>('get_info', 'info');
  }

  getPosture() {
    return unwrapped<Posture>('get_posture', 'posture');
  }

  listPlugins() {
    return unwrapped<PluginInfo[]>('list_plugins', 'plugins');
  }

  async listFindings(plugin?: string): Promise<Finding[]> {
    // The command takes no filter yet; filter client-side.
    const all = await unwrapped<Finding[]>('list_findings', 'findings');
    return plugin ? all.filter((f) => f.plugin === plugin) : all;
  }

  runChecks(): Promise<Finding[]> {
    return unwrapped<Finding[]>('run_checks', 'findings');
  }

  async setPluginEnabled(id: string, enabled: boolean): Promise<void> {
    await invoke('set_plugin_enabled', { id, enabled });
  }

  async getManifest(id: string): Promise<Record<string, unknown>> {
    return invoke('get_manifest', { id });
  }

  planChange(plugin: string, patch: Record<string, unknown>) {
    return unwrapped<Plan>('plan_change', 'plan', { plugin, patch });
  }

  apply(planId: string, confirmTimeoutSeconds?: number) {
    return unwrapped<Transaction>('apply', 'transaction', {
      planId,
      confirmTimeoutS: confirmTimeoutSeconds,
    });
  }

  async confirm(transactionId: string): Promise<void> {
    await invoke('confirm', { transactionId });
  }

  rollback(target: string) {
    return unwrapped<Transaction>('rollback', 'transaction', { target });
  }

  history(): Promise<HistoryEntry[]> {
    return unwrapped<HistoryEntry[]>('history', 'entries');
  }
}
