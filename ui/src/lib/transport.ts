// The UI talks to the core through this interface. The desktop app
// implements it with Tauri commands (varlink on the Rust side); tests and
// design work use the fixture implementation.
import type {
  AppDestination,
  FirewallState,
  AppEntry,
  ComplianceReport,
  DnsStatus,
  Finding,
  HistoryEntry,
  Info,
  MonitorStatus,
  Plan,
  PluginInfo,
  Posture,
  Prompt,
  Proposal,
  Transaction,
} from '../gen/contracts';

/** A compliance profile the machine can be evaluated against. */
export interface ComplianceProfileSummary {
  framework: string;
  version: string;
  controls: number;
}

/** A named varlink error, e.g. `com.ibexwall.Core.PermissionDenied`. */
export class TransportError extends Error {
  constructor(
    readonly code: string,
    readonly parameters: Record<string, unknown> = {},
  ) {
    super(code);
    this.name = 'TransportError';
  }

  get kind(): 'denied' | 'auth-required' | 'no-agent' | 'locked' | 'unreachable' | 'other' {
    if (this.code.endsWith('.PermissionDenied')) return 'denied';
    // ADR-0045: a password is needed. When the call already allowed the
    // dialog and still got this, no agent could show one.
    if (this.code.endsWith('.AuthenticationRequired')) {
      return this.parameters['interactive_possible'] === false ? 'no-agent' : 'auth-required';
    }
    if (this.code.endsWith('.Locked')) return 'locked';
    if (this.code === 'unreachable') return 'unreachable';
    return 'other';
  }
}

/** The message key that explains why a change did not happen. */
export function changeErrorKey(error: unknown): string {
  if (!(error instanceof TransportError)) return 'change-failed-other';
  switch (error.kind) {
    case 'denied':
      return 'auth-refused';
    case 'auth-required':
      return 'auth-required';
    case 'no-agent':
      return 'auth-no-agent';
    case 'locked':
      return 'change-locked';
    case 'unreachable':
      return 'change-unreachable';
    default:
      return 'change-failed-other';
  }
}

export type PromptScope = 'once' | 'destination' | 'always';

export interface AppsListing {
  monitor: MonitorStatus;
  apps: AppEntry[];
}

/** A new access token: shown once, with the plan patch that holds only its hash. */
export interface NewToken {
  token: string;
  patch: Record<string, unknown>;
}

export interface NewTokenRequest {
  name: string;
  preset: string;
  client?: string;
  expires?: string;
  /** The person's own secret; empty to have one generated. */
  secret?: string;
}

export interface Transport {
  getInfo(): Promise<Info>;
  getPosture(): Promise<Posture>;
  getDnsStatus(): Promise<DnsStatus>;
  getFirewall(): Promise<FirewallState>;
  listApps(): Promise<AppsListing>;
  getAppDestinations(app: string): Promise<AppDestination[]>;
  setAppMode(app: string, mode: string): Promise<void>;
  setDefaultMode(mode: string): Promise<void>;
  /** Connections held in Ask mode, oldest first. */
  listPrompts(): Promise<Prompt[]>;
  answerPrompt(id: string, decision: 'allow' | 'block', scope: PromptScope): Promise<void>;
  listPlugins(): Promise<PluginInfo[]>;
  listFindings(plugin?: string): Promise<Finding[]>;
  runChecks(plugin?: string): Promise<Finding[]>;
  setPluginEnabled(id: string, enabled: boolean): Promise<void>;
  getManifest(id: string): Promise<Record<string, unknown>>;
  planChange(plugin: string, patch: Record<string, unknown>): Promise<Plan>;
  apply(planId: string, confirmTimeoutSeconds?: number): Promise<Transaction>;
  confirm(transactionId: string): Promise<void>;
  rollback(target: string): Promise<Transaction>;
  history(limit?: number): Promise<HistoryEntry[]>;
  /** Changes an AI assistant proposed, newest first. */
  listProposals(status?: Proposal['status']): Promise<Proposal[]>;
  /** Approving applies the reviewed plan; the core refuses it if the plan changed. */
  decideProposal(id: string, decision: 'approve' | 'reject'): Promise<void>;
  /** Makes an access token on this machine; the secret never goes through the core. */
  makeAssistantToken(request: NewTokenRequest): Promise<NewToken>;
  /** Compliance profiles the machine can be evaluated against. */
  listCompliance(): Promise<ComplianceProfileSummary[]>;
  /** One profile's controls and their states. */
  getCompliance(profile: string): Promise<ComplianceReport>;
  /** Managed-mode: the effective config, locks and their sources. */
  getEffective(): Promise<{
    config: Record<string, unknown>;
    locks: string[];
    sources: Record<string, string>;
    /** An organisation's signed policy is applied (F11b). */
    managed: boolean;
  }>;
}
