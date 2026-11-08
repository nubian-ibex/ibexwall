// Transport backed by the Tauri commands (the Rust side is a varlink
// client). Errors arrive as { code, parameters } and become TransportError.
import type {
  AppDestination,
  FirewallState,
  DnsStatus,
  Finding,
  HistoryEntry,
  Info,
  ComplianceReport,
  Plan,
  PluginInfo,
  Posture,
  Prompt,
  Proposal,
  Transaction,
} from '../gen/contracts';
import {
  TransportError,
  type AppsListing,
  type ComplianceProfileSummary,
  type NewToken,
  type NewTokenRequest,
  type PromptScope,
  type Transport,
} from './transport';

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

  getDnsStatus() {
    return unwrapped<DnsStatus>('get_dns_status', 'dns_status');
  }

  getFirewall() {
    return unwrapped<FirewallState>('get_firewall', 'firewall');
  }

  listApps() {
    return invoke<AppsListing>('list_apps');
  }

  getAppDestinations(app: string) {
    return unwrapped<AppDestination[]>('get_app_destinations', 'destinations', { app });
  }

  async setAppMode(app: string, mode: string): Promise<void> {
    await invoke('set_app_mode', { app, mode });
  }

  async setDefaultMode(mode: string): Promise<void> {
    await invoke('set_default_mode', { mode });
  }

  listPrompts() {
    return unwrapped<Prompt[]>('list_prompts', 'prompts');
  }

  async answerPrompt(id: string, decision: 'allow' | 'block', scope: PromptScope): Promise<void> {
    await invoke('answer_prompt', { id, decision, scope });
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

  makeAssistantToken(request: NewTokenRequest) {
    return invoke<NewToken>('make_assistant_token', { ...request });
  }

  listCompliance() {
    return unwrapped<ComplianceProfileSummary[]>('list_compliance_profiles', 'profiles');
  }

  getCompliance(profile: string) {
    return unwrapped<ComplianceReport>('get_compliance', 'report', { profile });
  }

  getEffective() {
    return invoke<{
      config: Record<string, unknown>;
      locks: string[];
      sources: Record<string, string>;
    }>('get_effective');
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

  listProposals(status?: Proposal['status']) {
    return unwrapped<Proposal[]>('list_proposals', 'proposals', { status });
  }

  async decideProposal(id: string, decision: 'approve' | 'reject'): Promise<void> {
    await invoke('decide_proposal', { id, decision });
  }

  history(): Promise<HistoryEntry[]> {
    return unwrapped<HistoryEntry[]>('history', 'entries');
  }
}
