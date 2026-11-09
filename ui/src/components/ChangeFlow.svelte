<script lang="ts">
  // The reviewed-change flow every control plugin shares: simulate (show
  // exactly what would change), apply, keep within the deadline or undo.
  import { app } from '../lib/app.svelte';
  import { changeErrorKey, TransportError } from '../lib/transport';
  import { t } from '../lib/i18n.svelte';
  import type { Plan, Transaction } from '../gen/contracts';
  import Button from './Button.svelte';
  import Callouts from './Callouts.svelte';
  import ConfirmCountdown from './ConfirmCountdown.svelte';
  import DiffViewer from './DiffViewer.svelte';

  let { plugin, patch = {} }: { plugin: string; patch?: Record<string, unknown> } = $props();

  let plan = $state<Plan | null>(null);
  let busy = $state(false);
  let applied = $state<Transaction | null>(null);
  let keepCountdown = $state<Transaction | null>(null);
  let failure = $state<string | null>(null);

  function describe(error: unknown): string {
    // The core reports a named error with details; anything else is a
    // transport problem the app already describes elsewhere.
    if (error instanceof TransportError) {
      const field = error.parameters['field'];
      const reason = error.parameters['reason'];
      if (typeof reason === 'string') {
        return typeof field === 'string' ? `${field}: ${reason}` : reason;
      }
    }
    return t(changeErrorKey(error));
  }

  async function simulate() {
    busy = true;
    plan = null;
    failure = null;
    try {
      plan = await app.transport.planChange(plugin, patch);
    } catch (error) {
      failure = describe(error);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!plan) return;
    const planId = plan.id;
    busy = true;
    failure = null;
    try {
      applied = await app
        .waiting(() => app.transport.apply(planId))
        .catch((error: unknown) => {
          failure = describe(error);
          return null;
        });
      if (!applied) return;
      plan = null;
      if (applied.state === 'pending_confirm') keepCountdown = applied;
    } finally {
      busy = false;
    }
  }

  async function keep() {
    if (!keepCountdown) return;
    const keepId = keepCountdown.id;
    const kept = await app.change(() => app.transport.confirm(keepId));
    if (kept === undefined && app.notice) return;
    applied = { ...keepCountdown, state: 'committed' };
    keepCountdown = null;
    await app.refresh();
  }

  async function undo() {
    if (!applied) return;
    const id = applied.id;
    const undone = await app.change(() => app.transport.rollback(id));
    if (undone === undefined) return;
    applied = { ...applied, state: 'rolled_back' };
    keepCountdown = null;
    await app.refresh();
  }
</script>

{#if failure}
  <p class="failure" role="alert">
    <strong>{t('change-failed-title')}</strong>
    {failure}
  </p>
{/if}
<div class="actions">
  <Button {busy} onclick={simulate}>{t('simulate')}</Button>
  {#if plan}
    <Button variant="primary" {busy} onclick={apply}>{t('apply')}</Button>
  {/if}
</div>
{#if plan}
  {#if plan.ops.length === 0}
    <p class="muted">{t('simulate-empty')}</p>
  {:else}
    <DiffViewer ops={plan.ops} />
    <Callouts keys={plan.may_affect_keys ?? []} restorePoint="snapshots/next" />
  {/if}
{/if}
{#if applied}
  <p class="result">
    {t(applied.state === 'committed' ? 'applied-committed' : 'applied-rolled-back')}
  </p>
  {#if applied.state === 'committed'}
    <Button onclick={undo}>{t('undo-changes')}</Button>
  {/if}
{/if}
{#if keepCountdown}
  <ConfirmCountdown seconds={60} onkeep={keep} oncancel={undo} />
{/if}

<style>
  .actions {
    display: flex;
    gap: var(--space-3);
  }
  .muted {
    color: var(--muted);
  }
  .failure {
    margin: 0;
    padding: var(--space-3);
    background: var(--warning-soft);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-control);
    display: grid;
    gap: var(--space-1);
  }
  .result {
    font-weight: 600;
    color: var(--primary-strong);
  }
</style>
