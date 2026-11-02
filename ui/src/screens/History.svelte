<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import { relativeTime } from '../lib/time';
  import Button from '../components/Button.svelte';
  import StateMessage from '../components/StateMessage.svelte';

  let entries = $state<Awaited<ReturnType<typeof app.transport.history>> | null>(null);
  let busy = $state(false);

  async function load() {
    entries = null;
    entries = await app.transport.history(50);
  }
  load();

  async function undo(transaction: string) {
    busy = true;
    try {
      await app.transport.rollback(transaction);
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

{#if entries === null}
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
            <span class="mono">{entry.ts ? relativeTime(entry.ts, 'en') : ''}</span>
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
