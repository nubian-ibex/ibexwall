<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import Icon from '../components/Icon.svelte';
  import StateMessage from '../components/StateMessage.svelte';
  import type { TransportError } from '../lib/transport';

  type Load<T> =
    | { status: 'loading' }
    | { status: 'ready'; data: T }
    | { status: 'error'; error: TransportError };

  let effective = $state<Load<Awaited<ReturnType<typeof app.transport.getEffective>>>>({
    status: 'loading',
  });

  async function load() {
    effective = { status: 'loading' };
    try {
      effective = { status: 'ready', data: await app.transport.getEffective() };
    } catch (error) {
      effective = { status: 'error', error: error as TransportError };
    }
  }

  $effect(() => {
    void load();
  });
</script>

<header class="page-head">
  <div>
    <h1>{t('org-title')}</h1>
    <p class="muted">{t('org-subtitle')}</p>
  </div>
</header>

{#if effective.status === 'loading'}
  <StateMessage kind="loading" />
{:else if effective.status === 'error'}
  <StateMessage kind="error" onretry={() => load()} />
{:else if effective.data.locks.length === 0 && !effective.data.managed}
  <p class="muted">{t('org-empty')}</p>
{:else}
  <section class="banner">
    <Icon name="lock-keyhole" size={24} />
    <div>
      <h2>{t('org-managed')}</h2>
      <p>{t('org-synced')}</p>
    </div>
  </section>

  <p class="notice"><Icon name="shield-check" size={16} />{t('org-notice')}</p>

  <section>
    <h2>{t('org-rules')}</h2>
    <ul class="rules">
      {#each effective.data.locks as lock (lock)}
        <li>
          <Icon name="lock" size={14} />
          <span class="mono">{lock}</span>
          <span class="chip">{t('org-locked')}</span>
        </li>
      {/each}
    </ul>
  </section>

  <section class="transparency">
    <h2>{t('org-whats-sent')}</h2>
    <div class="cols">
      <div>
        <h3>{t('org-sent')}</h3>
        <ul>
          <li>{t('org-sent-posture')}</li>
          <li>{t('org-sent-findings')}</li>
          <li>{t('org-sent-versions')}</li>
          <li>{t('org-sent-audit')}</li>
        </ul>
      </div>
      <div>
        <h3>{t('org-never')}</h3>
        <ul>
          <li>{t('org-never-browsing')}</li>
          <li>{t('org-never-files')}</li>
          <li>{t('org-never-screen')}</li>
          <li>{t('org-never-keystrokes')}</li>
        </ul>
      </div>
    </div>
  </section>
{/if}

<style>
  .page-head {
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  h2 {
    font-size: 17px;
    font-weight: 600;
  }
  h3 {
    font-size: 14px;
    font-weight: 600;
  }
  .muted {
    color: var(--muted);
  }
  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-5);
    border-radius: var(--radius-card);
    background: var(--managed, #16263f);
    color: #fff;
    margin-bottom: var(--space-5);
  }
  .banner h2 {
    margin: 0;
  }
  .banner p {
    margin: var(--space-1) 0 0;
    font-size: 14px;
    color: var(--managed-soft, #c7d3e6);
  }
  .notice {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-4);
    border-radius: var(--radius-card);
    background: var(--surface);
    border: 1px solid var(--border);
    font-size: 14px;
    margin-bottom: var(--space-5);
  }
  .rules {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-1);
    margin-bottom: var(--space-5);
  }
  .rules li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3);
    border-radius: var(--radius-card);
    background: var(--surface);
    border: 1px solid var(--border);
  }
  .mono {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 13px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: var(--space-1) var(--space-2);
    border-radius: 999px;
    background: var(--info-soft, #e6eef9);
    color: var(--info, #1d4889);
    font-size: 12px;
    font-weight: 600;
    margin-left: auto;
  }
  .transparency {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
  }
  .cols {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-4);
  }
  .transparency ul {
    margin: var(--space-2) 0 0;
    padding: 0 0 0 var(--space-4);
    font-size: 13px;
    color: var(--muted);
    list-style: disc;
  }
  .transparency li {
    margin-bottom: var(--space-1);
  }
</style>
