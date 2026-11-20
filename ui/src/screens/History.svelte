<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { relativeTime } from '../lib/time';
  import Button from '../components/Button.svelte';
  import type { RestorePoint, RestorePointPlanEntry } from '../gen/contracts';
  import StateMessage from '../components/StateMessage.svelte';

  let entries = $state<Awaited<ReturnType<typeof app.transport.history>> | null>(null);
  let failed = $state(false);
  let busy = $state(false);

  let points = $state<RestorePoint[] | null>(null);
  /** The restore point whose undo list is being confirmed. */
  let chosen = $state<{ name: string; plan: RestorePointPlanEntry[] } | null>(null);
  let pointBusy = $state(false);
  let pointError = $state<string | null>(null);
  let newName = $state('');

  async function load() {
    entries = null;
    failed = false;
    try {
      entries = await app.transport.history(50);
      points = await app.transport.listRestorePoints();
    } catch {
      failed = true;
    }
  }
  load();

  async function createPoint() {
    const name = newName.trim();
    if (!name || pointBusy) return;
    pointBusy = true;
    pointError = null;
    try {
      await app.change(() => app.transport.createRestorePoint(name));
      if (app.notice) {
        pointError = t(app.notice);
      } else {
        newName = '';
        points = await app.transport.listRestorePoints();
      }
    } finally {
      pointBusy = false;
    }
  }

  async function planPoint(point: RestorePoint) {
    if (pointBusy) return;
    pointBusy = true;
    pointError = null;
    try {
      chosen = { name: point.name, plan: await app.transport.restorePointPlan(point.name) };
    } catch {
      pointError = t('change-unreachable');
    } finally {
      pointBusy = false;
    }
  }

  /** Going back undoes every change after the marker; the undo of each one is still in History. */
  async function goBack() {
    const point = chosen;
    if (!point || pointBusy) return;
    pointBusy = true;
    pointError = null;
    try {
      await app.change(() => app.transport.restorePointApply(point.name));
      if (!app.notice) chosen = null;
      await load();
    } finally {
      pointBusy = false;
    }
  }

  async function undo(transaction: string) {
    busy = true;
    try {
      await app.change(() => app.transport.rollback(transaction));
      await load();
    } finally {
      busy = false;
    }
  }
</script>

<header class="page-head">
  <div>
    <h1>{t('history-title')}</h1>
    <p class="muted">{t('history-subtitle')}</p>
  </div>
</header>

<section class="card" aria-labelledby="rp-title">
  <h2 id="rp-title">{t('history-rp-title')}</h2>
  <p class="muted">{t('history-rp-body')}</p>
  {#if pointError}<p class="point-error" role="alert">{pointError}</p>{/if}
  {#if points && points.length > 0}
    <ul class="points">
      {#each points as point (point.name)}
        <li>
          <span>
            <strong>{point.name}</strong>
            <span class="muted">{t('history-rp-after', { tx: point.tx })}</span>
          </span>
          <Button disabled={pointBusy || chosen !== null} onclick={() => planPoint(point)}>
            {t('history-rp-go')}
          </Button>
        </li>
      {/each}
    </ul>
  {:else if points}
    <p class="muted">{t('history-rp-empty')}</p>
  {/if}
  {#if chosen}
    <div class="confirm" role="group" aria-label={t('history-rp-plan')}>
      <p>{t('history-rp-plan-count', { count: chosen.plan.length, name: chosen.name })}</p>
      <ul class="mono">
        {#each chosen.plan as row (row.transaction)}
          <li>{row.transaction} · {row.plugin} · {t(`history-state-${row.state}`)}</li>
        {/each}
      </ul>
      <div class="actions">
        <Button disabled={pointBusy} onclick={() => (chosen = null)}>{t('panel-close')}</Button>
        <Button variant="primary" disabled={pointBusy} onclick={goBack}>{t('undo-changes')}</Button>
      </div>
    </div>
  {/if}
  <div class="actions create">
    <label class="name">
      <span>{t('history-rp-name')}</span>
      <input
        type="text"
        bind:value={newName}
        placeholder={t('history-rp-name-hint')}
        maxlength="64"
        onkeydown={(e) => e.key === 'Enter' && createPoint()}
      />
    </label>
    <Button disabled={pointBusy || newName.trim() === ''} onclick={createPoint}>
      {t('history-rp-create')}
    </Button>
  </div>
</section>

{#if failed}
  <StateMessage kind="error" onretry={load} />
{:else if entries === null}
  <StateMessage kind="loading" />
{:else if entries.length === 0}
  <section class="empty">
    <h2>{t('history-empty-title')}</h2>
    <p>{t('history-empty-body')}</p>
  </section>
{:else}
  <ul class="list">
    {#each entries as entry (entry.seq)}
      <li>
        <article class="row">
          <div class="when">
            <strong>{t(`history-result-${entry.result.replace(/_/g, '_')}`)}</strong>
            <span class="mono">{entry.plugin}</span>
          </div>
          <div class="who">
            <span
              >{entry.actor === 'system'
                ? t('history-actor-system')
                : t('history-actor-user', { actor: entry.actor })}</span
            >
            <span class="mono">{entry.ts ? relativeTime(entry.ts, i18n.locale) : ''}</span>
          </div>
          {#if entry.transaction && entry.result === 'committed'}
            <Button {busy} onclick={() => undo(entry.transaction!)}>{t('history-undo')}</Button>
          {:else}
            <span></span>
          {/if}
        </article>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    margin-bottom: var(--space-6);
    display: grid;
    gap: var(--space-3);
  }
  .points {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  .points li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-2) 0;
    border-bottom: 1px solid var(--divider);
  }
  .confirm {
    border: 1px solid var(--warning-border);
    background: var(--warning-soft);
    border-radius: var(--radius-control);
    padding: var(--space-3) var(--space-4);
    display: grid;
    gap: var(--space-2);
  }
  .actions {
    display: flex;
    gap: var(--space-3);
    align-items: center;
  }
  .actions.create {
    justify-content: flex-end;
  }
  .name {
    display: grid;
    gap: var(--space-1);
    font-size: 14px;
    flex: 1;
    max-width: 320px;
  }
  .point-error {
    color: var(--danger-strong);
  }

  .page-head {
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  .muted {
    color: var(--muted);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .row {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: var(--space-4);
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4) var(--space-5);
  }
  .when {
    display: grid;
  }
  .who {
    display: grid;
    color: var(--text-2);
    font-size: 14px;
  }
  .empty {
    display: grid;
    gap: var(--space-2);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-8);
    max-width: 640px;
  }
  .empty p {
    color: var(--text-2);
  }
</style>
