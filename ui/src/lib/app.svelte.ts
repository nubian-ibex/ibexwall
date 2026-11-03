import type { Finding, PluginInfo, Posture, Prompt } from '../gen/contracts';
import { FixtureTransport, type Scenario } from './fixtures';
import { insideTauri, TauriTransport } from './tauri-transport';
import { TransportError, type Transport } from './transport';

export type Route =
  'overview' | 'apps' | 'firewall' | 'dns' | 'plugins' | 'posture' | 'history' | 'settings';

type Load<T> =
  { status: 'loading' } | { status: 'ready'; data: T } | { status: 'error'; error: TransportError };

class AppState {
  // The real shell uses the Tauri commands; a plain browser (tests, e2e,
  // design work) uses the fixture core.
  transport: Transport = insideTauri()
    ? new TauriTransport()
    : new FixtureTransport(initialScenario(), 0, wantsPrompt());
  route = $state<Route>('overview');
  posture = $state<Load<Posture>>({ status: 'loading' });
  findings = $state<Load<Finding[]>>({ status: 'loading' });
  plugins = $state<Load<PluginInfo[]>>({ status: 'loading' });
  checking = $state(false);
  /** Connections held in Ask mode, waiting for an answer. */
  prompts = $state<Prompt[]>([]);

  useTransport(transport: Transport) {
    this.transport = transport;
  }

  async refresh() {
    this.posture = { status: 'loading' };
    this.findings = { status: 'loading' };
    this.plugins = { status: 'loading' };
    await Promise.all([
      this.load(
        () => this.transport.getPosture(),
        (v) => (this.posture = v),
      ),
      this.load(
        () => this.transport.listFindings(),
        (v) => (this.findings = v),
      ),
      this.load(
        () => this.transport.listPlugins(),
        (v) => (this.plugins = v),
      ),
    ]);
  }

  /** Polls the open questions; failures leave the list as it was. */
  async refreshPrompts() {
    try {
      this.prompts = await this.transport.listPrompts();
    } catch {
      // The core may be starting or the user may lack permission; the
      // other screens already say so.
    }
  }

  /** "Check now": run the checks, then reload what depends on them. */
  async checkNow() {
    this.checking = true;
    try {
      await this.transport.runChecks();
    } catch (error) {
      this.posture = { status: 'error', error: asTransportError(error) };
      return;
    } finally {
      this.checking = false;
    }
    await this.refresh();
  }

  private async load<T>(fetch: () => Promise<T>, set: (value: Load<T>) => void) {
    try {
      set({ status: 'ready', data: await fetch() });
    } catch (error) {
      set({ status: 'error', error: asTransportError(error) });
    }
  }
}

function asTransportError(error: unknown): TransportError {
  return error instanceof TransportError ? error : new TransportError('unreachable');
}

function initialScenario(): Scenario {
  const wanted = new URLSearchParams(globalThis.location?.search ?? '').get('scenario');
  const known: Scenario[] = ['attention', 'protected', 'empty', 'error', 'denied'];
  return known.find((s) => s === wanted) ?? 'attention';
}

/** `?prompts=1` seeds the fixture core with one held connection. */
function wantsPrompt(): boolean {
  return new URLSearchParams(globalThis.location?.search ?? '').get('prompts') === '1';
}

export const app = new AppState();
