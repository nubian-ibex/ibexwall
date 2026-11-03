import type { Finding, PluginInfo, Posture } from '../gen/contracts';
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
    : new FixtureTransport(initialScenario());
  route = $state<Route>('overview');
  posture = $state<Load<Posture>>({ status: 'loading' });
  findings = $state<Load<Finding[]>>({ status: 'loading' });
  plugins = $state<Load<PluginInfo[]>>({ status: 'loading' });
  checking = $state(false);

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

export const app = new AppState();
