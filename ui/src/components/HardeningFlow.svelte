<script lang="ts">
  // The reviewed change for several hardening items at once. The items go to
  // different plugins, so there is one plan and one transaction per plugin:
  // they are shown together, applied one after the other, and undone in
  // reverse. Nothing is applied by simulating.
  import { app } from '../lib/app.svelte';
  import { TransportError } from '../lib/transport';
  import { t } from '../lib/i18n.svelte';
  import { groupByPlugin, type Item } from '../lib/hardening';
  import type { Plan, Transaction } from '../gen/contracts';
  import Button from './Button.svelte';
  import Callouts from './Callouts.svelte';
  import DiffViewer from './DiffViewer.svelte';

  let { items, ondone }: { items: Item[]; ondone?: () => void } = $props();

  let plans = $state<Plan[]>([]);
  let applied = $state<Transaction[]>([]);
  let pending = $state<Transaction[]>([]);
  let busy = $state(false);
  let failure = $state<string | null>(null);
  let undone = $state(false);

  function describe(error: unknown): string {
    if (error instanceof TransportError) {
      const reason = error.parameters['reason'];
      const field = error.parameters['field'];
      if (typeof reason === 'string') {
        return typeof field === 'string' ? `${field}: ${reason}` : reason;
      }
    }
    return t('change-failed-other');
  }

  async function simulate() {
    busy = true;
    failure = null;
    plans = [];
    applied = [];
    pending = [];
    undone = false;
    try {
      const made: Plan[] = [];
      for (const group of groupByPlugin(items)) {
        made.push(await app.transport.planChange(group.plugin, group.patch));
      }
      plans = made;
    } catch (error) {
      failure = describe(error);
    } finally {
      busy = false;
    }
  }

  async function applyAll() {
    busy = true;
    failure = null;
    try {
      for (const plan of plans) {
        const tx = await app.transport.apply(plan.id);
        applied = [...applied, tx];
        if (tx.state === 'pending_confirm') pending = [...pending, tx];
        if (tx.state === 'failed' || tx.state === 'rolled_back') {
          failure = t('hardening-stopped', { plugin: plan.plugin });
          break;
        }
      }
      plans = [];
    } catch (error) {
      failure = describe(error);
    } finally {
      busy = false;
      await app.refresh();
      ondone?.();
    }
  }

  async function keepAll() {
    for (const tx of pending) await app.transport.confirm(tx.id);
    applied = applied.map((a) =>
      pending.some((p) => p.id === a.id) ? { ...a, state: 'committed' } : a,
    );
    pending = [];
  }

  async function undoAll() {
    busy = true;
    try {
      for (const tx of [...applied].reverse()) {
        if (tx.state === 'committed' || tx.state === 'pending_confirm') {
          await app.transport.rollback(tx.id);
        }
      }
      undone = true;
      applied = [];
      pending = [];
    } catch (error) {
      failure = describe(error);
    } finally {
      busy = false;
      await app.refresh();
      ondone?.();
    }
  }
</script>

{#if failure}
  <p class="failure" role="alert">
    <strong>{t('change-failed-title')}</strong>
    {failure}
  </p>
{/if}

<div class="actions">
  <Button {busy} onclick={simulate} disabled={items.length === 0}>{t('hardening-review')}</Button>
  {#if plans.length > 0}
    <Button variant="primary" {busy} onclick={applyAll}
      >{t('hardening-apply', { count: items.length })}</Button
    >
  {/if}
</div>

{#each plans as plan (plan.id)}
  <section class="plan" aria-label={plan.plugin}>
    <h3 class="mono">{plan.plugin}</h3>
    {#if plan.ops.length === 0}
      <p class="muted">{t('simulate-empty')}</p>
    {:else}
      <DiffViewer ops={plan.ops} />
      <Callouts keys={plan.may_affect_keys ?? []} restorePoint="snapshots/next" />
    {/if}
  </section>
{/each}

{#if applied.length > 0}
  <p class="result" role="status">{t('hardening-applied', { count: applied.length })}</p>
  {#if pending.length > 0}
    <p>{t('hardening-keep-body')}</p>
    <Button variant="primary" onclick={keepAll}>{t('hardening-keep')}</Button>
  {/if}
  <Button {busy} onclick={undoAll}>{t('hardening-undo')}</Button>
{/if}
{#if undone}
  <p class="result" role="status">{t('hardening-undone')}</p>
{/if}

<style>
  .actions {
    display: flex;
    gap: var(--space-3);
    margin: var(--space-3) 0;
  }
  .plan {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4);
    margin-bottom: var(--space-3);
    display: grid;
    gap: var(--space-2);
  }
  .muted {
    color: var(--muted);
  }
  .failure {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-3) var(--space-4);
  }
</style>
