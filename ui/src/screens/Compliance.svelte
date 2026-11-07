<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { relativeTime } from '../lib/time';
  import { TransportError, type ComplianceProfileSummary } from '../lib/transport';
  import type { ComplianceReport, ComplianceStatus } from '../gen/contracts';
  import Icon from '../components/Icon.svelte';
  import StateMessage from '../components/StateMessage.svelte';

  type Load<T> =
    | { status: 'loading' }
    | { status: 'ready'; data: T }
    | { status: 'error'; error: TransportError };

  const ORDER: ComplianceStatus[] = [
    'compliant',
    'non_compliant',
    'not_assessed',
    'needs_attestation',
    'excepted',
    'not_applicable',
  ];

  let profiles = $state<Load<ComplianceProfileSummary[]>>({ status: 'loading' });
  let selected = $state<string | null>(null);
  let report = $state<Load<ComplianceReport>>({ status: 'loading' });

  async function loadProfiles() {
    profiles = { status: 'loading' };
    try {
      profiles = { status: 'ready', data: await app.transport.listCompliance() };
    } catch (error) {
      profiles = { status: 'error', error: error as TransportError };
    }
  }

  async function open(profile: string) {
    selected = profile;
    report = { status: 'loading' };
    try {
      report = { status: 'ready', data: await app.transport.getCompliance(profile) };
    } catch (error) {
      report = { status: 'error', error: error as TransportError };
    }
  }

  $effect(() => {
    void loadProfiles();
  });

  const counts = $derived.by(() => {
    if (report.status !== 'ready') return null;
    const tally: Partial<Record<ComplianceStatus, number>> = {};
    for (const control of report.data.controls) {
      tally[control.status] = (tally[control.status] ?? 0) + 1;
    }
    return tally;
  });
</script>

<header class="page-head">
  <div>
    <h1>{t('compliance-title')}</h1>
    <p class="muted">{t('compliance-subtitle')}</p>
  </div>
</header>

{#if profiles.status === 'loading'}
  <StateMessage kind="loading" />
{:else if profiles.status === 'error'}
  <StateMessage kind="error" onretry={() => loadProfiles()} />
{:else if profiles.data.length === 0}
  <p class="muted">{t('compliance-empty')}</p>
{:else}
  <nav class="profiles" aria-label={t('compliance-profiles')}>
    {#each profiles.data as profile (profile.framework)}
      <button
        type="button"
        class:active={selected === profile.framework}
        onclick={() => open(profile.framework)}
      >
        <span class="name">{profile.framework}</span>
        <span class="version">{profile.version}</span>
        <span class="count">{t('compliance-controls', { count: profile.controls })}</span>
      </button>
    {/each}
  </nav>

  {#if selected}
    {#if report.status === 'loading'}
      <StateMessage kind="loading" />
    {:else if report.status === 'error'}
      <StateMessage kind="error" onretry={() => open(selected!)} />
    {:else}
      <p class="evaluated muted">
        {t('compliance-evaluated', {
          when: relativeTime(report.data.evaluated_at, i18n.locale),
        })}
      </p>

      {#if counts}
        <ul class="summary">
          {#each ORDER as status (status)}
            {@const n = counts[status] ?? 0}
            {#if n > 0}
              <li class="chip {status}">
                <Icon name="circle-question-mark" size={14} />
                {t(`compliance-status-${status.replace(/_/g, '-')}`)}
                <span class="mono">{n}</span>
              </li>
            {/if}
          {/each}
        </ul>
      {/if}

      <ul class="controls">
        {#each report.data.controls as control (control.control_id)}
          <li>
            <span class="badge {control.status}">
              {t(`compliance-status-${control.status.replace(/_/g, '-')}`)}
            </span>
            <div>
              <span class="title">{control.title}</span>
              <span class="id mono">{control.control_id}</span>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}

  <p class="limit muted">
    <Icon name="circle-question-mark" size={14} />{t('compliance-not-certified')}
  </p>
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
  .profiles {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-bottom: var(--space-6);
  }
  .profiles button {
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    background: var(--surface);
    padding: var(--space-3) var(--space-4);
    cursor: pointer;
    display: grid;
    gap: var(--space-1);
    text-align: left;
    min-width: 220px;
  }
  .profiles button.active {
    border-color: var(--accent);
    box-shadow: inset 0 0 0 1px var(--accent);
  }
  .profiles .name {
    font-weight: 600;
  }
  .profiles .version,
  .profiles .count,
  .evaluated {
    font-size: 13px;
  }
  .summary {
    list-style: none;
    margin: 0 0 var(--space-5);
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: var(--space-1) var(--space-3);
    font-size: 13px;
  }
  .controls {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  .controls li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    background: var(--surface);
    padding: var(--space-3) var(--space-4);
  }
  .controls .badge {
    flex: none;
    font-size: 12px;
    border-radius: 999px;
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--border);
    white-space: nowrap;
  }
  .controls .title {
    display: block;
  }
  .controls .id {
    display: block;
    font-size: 12px;
    color: var(--muted);
  }
  .compliant {
    color: var(--ok, #1a7f37);
  }
  .non_compliant {
    color: var(--danger, #cf222e);
  }
  .needs_attestation,
  .not_assessed {
    color: var(--warning, #9a6700);
  }
  .limit {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-top: var(--space-5);
    font-size: 13px;
  }
</style>
