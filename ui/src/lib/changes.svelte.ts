// The changes a person has queued, and the review panel that carries them
// out. Screens that gather several choices (Hardening, DNS) keep their
// choices here as `drafts`, and the change bar shows them; a screen with one
// deliberate action calls `propose`, which opens the review at once. The
// store only holds what is wanted: the daemon still plans, applies, confirms
// and rolls back, through the panel.

import { untrack } from 'svelte';

export interface Draft {
  id: string;
  /** The screen that owns it (a route name), so it can replace or clear it. */
  source: string;
  plugin: string;
  patch: Record<string, unknown>;
  /** How many changes the person sees in it (a plugin's patch may carry several). */
  count: number;
  /** A short name for the bar: the screen's area. */
  label: string;
}

class Changes {
  /** Queued by screens; shown in the change bar. */
  drafts = $state<Draft[]>([]);
  /** What the open review panel works on, or null while it is closed. */
  panel = $state<Draft[] | null>(null);
  private listeners = new Set<() => void>();

  get total(): number {
    return this.drafts.reduce((sum, d) => sum + d.count, 0);
  }

  countFor(source: string): number {
    return this.drafts.filter((d) => d.source === source).reduce((sum, d) => sum + d.count, 0);
  }

  /** Replaces what one screen has queued. */
  setSource(source: string, drafts: Omit<Draft, 'source'>[]) {
    // Read without tracking: a screen calls this from an effect, which must
    // not depend on the list it is writing.
    const others = untrack(() => this.drafts).filter((d) => d.source !== source);
    this.drafts = [...others, ...drafts.map((d) => ({ ...d, source }))];
  }

  /** Drops what one screen queued, or everything. */
  discard(source?: string) {
    this.drafts = source ? untrack(() => this.drafts).filter((d) => d.source !== source) : [];
  }

  /** Opens the review for everything queued. */
  review() {
    if (this.drafts.length > 0) this.panel = [...this.drafts];
  }

  /** Opens the review for one deliberate action. */
  propose(plugin: string, patch: Record<string, unknown> = {}, label = '') {
    this.panel = [{ id: `direct-${plugin}`, source: 'direct', plugin, patch, count: 1, label }];
  }

  close() {
    this.panel = null;
  }

  /** Called when the machine changed (applied, kept or undone), so a screen can read its state again. */
  onApplied(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notify() {
    for (const listener of [...this.listeners]) listener();
  }
}

export const changes = new Changes();
