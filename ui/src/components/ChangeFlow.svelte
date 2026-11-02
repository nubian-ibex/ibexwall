<script lang="ts">
  // The reviewed-change flow every control plugin shares: simulate (show
  // exactly what would change), apply, keep within the deadline or undo.
  import { app } from '../lib/app.svelte';
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

  async function simulate() {
    busy = true;
    plan = null;
    try {
      plan = await app.transport.planChange(plugin, patch);
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!plan) return;
    busy = true;
    try {
      applied = await app.transport.apply(plan.id);
      plan = null;
      if (applied.state === 'pending_confirm') keepCountdown = applied;
    } finally {
      busy = false;
    }
  }

  async function keep() {
    if (!keepCountdown) return;
    await app.transport.confirm(keepCountdown.id);
    applied = { ...keepCountdown, state: 'committed' };
    keepCountdown = null;
    await app.refresh();
  }

  async function undo() {
    if (!applied) return;
    await app.transport.rollback(applied.id);
    applied = { ...applied, state: 'rolled_back' };
    keepCountdown = null;
    await app.refresh();
  }
</script>

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
  .result {
    font-weight: 600;
    color: var(--primary-strong);
  }
</style>
