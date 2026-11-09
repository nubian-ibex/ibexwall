import type { Finding, PluginInfo, Posture, Prompt } from '../gen/contracts';
import { FixtureTransport, type Scenario } from './fixtures';
import { insideTauri, TauriTransport } from './tauri-transport';
import { changeErrorKey, TransportError, type Transport } from './transport';

export type Route =
  | 'overview'
  | 'apps'
  | 'firewall'
  | 'dns'
  | 'plugins'
  | 'posture'
  | 'history'
  | 'assistant'
  | 'hardening'
  | 'compliance'
  | 'organisation'
  | 'settings';

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
  /** Changes sent to the daemon and not answered yet: while one waits,
   * the system may be showing a password dialog (ADR-0045). */
  changing = $state(0);
  /** Why the last change did not happen, as a message key. */
  notice = $state<string | null>(null);

  /** Runs a change, counting it as pending; errors propagate. */
  async waiting<T>(work: () => Promise<T>): Promise<T> {
    this.changing += 1;
    try {
      return await work();
    } finally {
      this.changing -= 1;
    }
  }

  /** Runs a change and reports a failure in the notice instead of
   * throwing; the result is undefined when it failed. */
  async change<T>(work: () => Promise<T>): Promise<T | undefined> {
    this.notice = null;
    try {
      return await this.waiting(work);
    } catch (error) {
      this.notice = changeErrorKey(error);
      return undefined;
    }
  }

  dismissNotice() {
    this.notice = null;
  }

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
  const query = new URLSearchParams(globalThis.location?.search ?? '');
  return query.get('prompts') === '1' || query.get('window') === 'prompt';
}

export const app = new AppState();
