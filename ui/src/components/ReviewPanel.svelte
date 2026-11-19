<script lang="ts">
  // The review of queued changes, in three visible steps: Review (the exact
  // plan, nothing changed yet), Apply, Keep (or undo, before the deadline the
  // core set). Each draft is one plan and one transaction, applied in order
  // and undone in reverse; a failure part-way leaves an accurate list, and a
  // retry only repeats what is still open.
  import { onMount, tick } from 'svelte';
  import { app } from '../lib/app.svelte';
  import { changes, type Draft } from '../lib/changes.svelte';
  import { changeErrorKey, TransportError } from '../lib/transport';
  import { t } from '../lib/i18n.svelte';
  import type { Plan, Transaction } from '../gen/contracts';
  import Button from './Button.svelte';
  import Callouts from './Callouts.svelte';
  import ConfirmCountdown from './ConfirmCountdown.svelte';
  import DiffViewer from './DiffViewer.svelte';
  import Icon from './Icon.svelte';

  let { drafts }: { drafts: Draft[] } = $props();

  type Phase = 'review' | 'applying' | 'keep' | 'done';
  type Outcome = 'kept' | 'undone' | 'expired' | 'stopped';

  let phase = $state<Phase>('review');
  let outcome = $state<Outcome | null>(null);
  let planning = $state(true);
  let plans = $state<Plan[]>([]);
  let applied = $state<Transaction[]>([]);
  let pending = $state<Transaction[]>([]);
  let failure = $state<string | null>(null);
  // Keep and Undo share one in-flight guard against a double click.
  let acting = $state(false);
  let heading: HTMLElement | undefined = $state();
  let opener: Element | null = null;

  const empty = $derived(!planning && plans.length > 0 && plans.every((p) => p.ops.length === 0));
  const canApply = $derived(!planning && !failure && plans.length > 0 && !empty);
  const step = $derived(phase === 'review' ? 1 : phase === 'applying' ? 2 : 3);
  const steps = ['panel-step-review', 'panel-step-apply', 'panel-step-keep'];
  const total = $derived(drafts.reduce((sum, d) => sum + d.count, 0));
  const deadline = $derived(
    pending
      .map((p) => p.confirm_deadline)
      .filter((d): d is string => !!d)
      .sort()[0] ?? null,
  );
  const canUndo = $derived(applied.some((a) => a.state === 'committed'));

  function describe(error: unknown): string {
    if (error instanceof TransportError) {
      const reason = error.parameters['reason'];
      const field = error.parameters['field'];
      if (typeof reason === 'string') {
        return typeof field === 'string' ? `${field}: ${reason}` : reason;
      }
    }
    return t(changeErrorKey(error));
  }

  onMount(() => {
    opener = document.activeElement;
    void (async () => {
      try {
        const made: Plan[] = [];
        for (const draft of drafts)
          made.push(await app.transport.planChange(draft.plugin, draft.patch));
        plans = made;
      } catch (error) {
        failure = describe(error);
      } finally {
        planning = false;
      }
      await tick();
      heading?.focus();
    })();
    return () => {
      if (opener instanceof HTMLElement) opener.focus();
    };
  });

  async function settled() {
    await app.refresh();
    changes.notify();
  }

  async function applyAll() {
    // A click can land while the plans are still being prepared.
    if (!canApply || phase !== 'review') return;
    phase = 'applying';
    failure = null;
    try {
      for (const plan of plans) {
        const tx = await app.waiting(() => app.transport.apply(plan.id));
        applied = [...applied, tx];
        if (tx.state === 'pending_confirm') pending = [...pending, tx];
        if (tx.state === 'failed' || tx.state === 'rolled_back') {
          failure = t('hardening-stopped', { plugin: plan.plugin });
          break;
        }
      }
    } catch (error) {
      failure = describe(error);
    }
    if (pending.length > 0) {
      phase = 'keep';
    } else {
      phase = 'done';
      outcome = applied.some((a) => a.state === 'committed') ? 'kept' : 'stopped';
    }
    await settled();
  }

  // Each transaction's state is updated as soon as its own call succeeds.
  function mark(id: string, state: Transaction['state']) {
    applied = applied.map((a) => (a.id === id ? { ...a, state } : a));
    pending = pending.filter((p) => p.id !== id);
  }

  async function keepAll() {
    if (acting) return;
    acting = true;
    failure = null;
    try {
      for (const tx of [...pending]) {
        await app.waiting(() => app.transport.confirm(tx.id));
        mark(tx.id, 'committed');
      }
      phase = 'done';
      outcome = 'kept';
      await settled();
    } catch (error) {
      failure = describe(error);
    } finally {
      acting = false;
    }
  }

  async function undoAll() {
    if (acting) return;
    acting = true;
    failure = null;
    try {
      for (const tx of [...applied].reverse()) {
        if (tx.state === 'committed' || tx.state === 'pending_confirm') {
          await app.waiting(() => app.transport.rollback(tx.id));
          mark(tx.id, 'rolled_back');
        }
      }
      phase = 'done';
      outcome = 'undone';
      await settled();
    } catch (error) {
      failure = describe(error);
    } finally {
      acting = false;
    }
  }

  // The deadline passed without an answer: the core undoes the changes by
  // itself, so say so instead of leaving a countdown stuck at zero.
  async function expire() {
    if (phase !== 'keep' || acting) return;
    for (const tx of [...pending]) mark(tx.id, 'rolled_back');
    phase = 'done';
    outcome = 'expired';
    await settled();
  }

  function close() {
    if (phase === 'applying' || phase === 'keep') return;
    changes.close();
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') close();
  }
</script>

<svelte:window {onkeydown} />

<div class="scrim" aria-hidden="true" onclick={close}></div>
<div class="panel" role="dialog" aria-modal="true" aria-labelledby="review-title">
  <header>
    <div class="top">
      <h2 id="review-title" tabindex="-1" bind:this={heading}>
        {t(
          phase === 'review'
            ? 'panel-title-review'
            : phase === 'applying'
              ? 'panel-title-applying'
              : phase === 'keep'
                ? 'panel-title-keep'
                : 'panel-title-done',
        )}
      </h2>
      {#if phase === 'review' || phase === 'done'}
        <button type="button" class="x" aria-label={t('panel-close')} onclick={close}>
          <Icon name="x" size={20} />
        </button>
      {/if}
    </div>
    <ol class="steps" aria-label={t('panel-steps-label')}>
      {#each steps as key, i (key)}
        <li
          class:current={phase !== 'done' && step === i + 1}
          class:done={phase === 'done' || step > i + 1}
          aria-current={phase !== 'done' && step === i + 1 ? 'step' : undefined}
        >
          <span class="n" aria-hidden="true">{phase === 'done' || step > i + 1 ? '✓' : i + 1}</span>
          {t(key)}
        </li>
      {/each}
    </ol>
  </header>

  <div class="body">
    {#if app.changing > 0}
      <p class="note waiting" role="status">{t('change-waiting')}</p>
    {/if}
    {#if failure}
      <p class="note failure" role="alert">
        <strong>{t('change-failed-title')}</strong>
        {failure}
      </p>
    {/if}

    {#if phase === 'review'}
      {#if planning}
        <p class="muted" role="status">{t('panel-planning')}</p>
      {:else}
        {#if plans.length > 0}
          <p class="muted">{t('panel-review-note')}</p>
        {/if}
        {#if empty}
          <p class="muted">{t('simulate-empty')}</p>
        {/if}
        {#each plans as plan (plan.id)}
          {#if plan.ops.length > 0}
            <section class="plan" aria-label={plan.plugin}>
              {#if plans.length > 1}<h3 class="mono">{plan.plugin}</h3>{/if}
              <DiffViewer ops={plan.ops} />
              <Callouts keys={plan.may_affect_keys ?? []} restorePoint="snapshots/next" />
            </section>
          {/if}
        {/each}
      {/if}
    {:else if phase === 'applying'}
      <p class="muted" role="status">{t('panel-applying-note')}</p>
    {:else if phase === 'keep'}
      <p class="muted">{t('panel-keep-note')}</p>
      <ConfirmCountdown
        {deadline}
        busy={acting}
        onkeep={keepAll}
        oncancel={undoAll}
        onexpire={expire}
      />
    {:else}
      <p class="result" role="status">
        {#if outcome === 'kept'}
          {t('hardening-applied', { count: applied.length })}
        {:else if outcome === 'undone'}
          {t('hardening-undone')}
        {:else if outcome === 'expired'}
          {t('panel-expired')}
        {:else}
          {t('panel-stopped')}
        {/if}
      </p>
    {/if}
  </div>

  <footer>
    {#if phase === 'review'}
      <Button variant="secondary" onclick={close}>{t('panel-close')}</Button>
      <span class="grow"></span>
      <Button variant="primary" disabled={!canApply} onclick={applyAll}>
        {t('panel-apply', { count: total })}
      </Button>
    {:else if phase === 'done'}
      {#if canUndo}
        <Button busy={acting} onclick={undoAll}>{t('hardening-undo')}</Button>
      {/if}
      <span class="grow"></span>
      <Button variant="primary" onclick={close}>{t('panel-close')}</Button>
    {/if}
  </footer>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 30;
    background: rgba(10, 16, 13, 0.4);
  }
  .panel {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    z-index: 40;
    width: min(520px, 100%);
    display: flex;
    flex-direction: column;
    background: var(--surface);
    border-left: 1px solid var(--border);
    box-shadow: -10px 0 40px rgba(22, 32, 28, 0.18);
  }
  header {
    padding: var(--space-5) var(--space-6) 0;
  }
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  h2 {
    font-size: 20px;
    outline: none;
  }
  .x {
    min-width: var(--target);
    min-height: var(--target);
    border: 0;
    background: transparent;
    border-radius: var(--radius-control);
    cursor: pointer;
    color: var(--text-2);
  }
  .x:hover {
    background: var(--surface-2);
  }
  .steps {
    list-style: none;
    margin: var(--space-4) 0 0;
    padding: 0 0 var(--space-4);
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
    border-bottom: 1px solid var(--divider);
  }
  .steps li {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--muted);
    font-size: 14px;
    font-weight: 500;
  }
  .n {
    flex: none;
    width: 24px;
    height: 24px;
    display: grid;
    place-items: center;
    border-radius: 50%;
    border: 2px solid var(--border-strong);
    font-size: 12px;
    font-weight: 700;
  }
  .steps li.current {
    color: var(--text);
    font-weight: 600;
  }
  .steps li.current .n {
    background: var(--primary);
    border-color: var(--primary);
    color: var(--on-primary);
  }
  .steps li.done .n {
    background: var(--primary-soft);
    border-color: var(--primary);
    color: var(--primary-strong);
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--space-5) var(--space-6);
    display: grid;
    align-content: start;
    gap: var(--space-3);
  }
  footer {
    display: flex;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-6);
    border-top: 1px solid var(--border);
  }
  .grow {
    flex: 1;
  }
  .muted {
    color: var(--muted);
  }
  .plan {
    display: grid;
    gap: var(--space-2);
  }
  .note {
    margin: 0;
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-control);
    border: 1px solid var(--border);
  }
  .note.waiting {
    background: var(--info-soft);
    border-color: transparent;
  }
  .note.failure {
    background: var(--warning-soft);
    border-color: var(--warning-border);
    display: grid;
    gap: var(--space-1);
  }
  .result {
    font-weight: 600;
    color: var(--primary-strong);
    font-size: 17px;
  }
  @media (prefers-color-scheme: dark) {
    .panel {
      box-shadow: -10px 0 40px rgba(0, 0, 0, 0.5);
    }
  }
</style>
