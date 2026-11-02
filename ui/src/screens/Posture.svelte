<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { cardsFrom } from '../lib/protections';
  import { topRecommendation } from '../lib/status';
  import { relativeTime } from '../lib/time';
  import type { CheckResult } from '../gen/contracts';
  import Icon from '../components/Icon.svelte';
  import FindingRow from '../components/FindingRow.svelte';
  import SeverityBadge from '../components/SeverityBadge.svelte';
  import StateMessage from '../components/StateMessage.svelte';

  const WEIGHTS: [CheckResult['severity'], string][] = [
    ['critical', '10'],
    ['high', '6'],
    ['medium', '3'],
    ['low', '1'],
    ['info', '0'],
  ];

  const posture = $derived(app.posture);
  const results = $derived(posture.status === 'ready' ? (posture.data.results ?? []) : []);
  const findings = $derived(app.findings.status === 'ready' ? app.findings.data : []);
</script>

<header class="page-head">
  <div>
    <h1>{t('posture-title')}</h1>
    <p class="muted">
      {posture.status === 'ready'
        ? t('overview-last-check', {
            when: relativeTime(posture.data.generated_at, i18n.locale),
          })
        : t('posture-subtitle')}
    </p>
  </div>
</header>

{#if posture.status === 'loading'}
  <StateMessage kind="loading" />
{:else if posture.status === 'error'}
  <StateMessage kind="error" onretry={() => app.refresh()} />
{:else}
  {@const recommendation = topRecommendation(results)}
  {#if recommendation}
    <section class="recommendation" aria-labelledby="rec-title">
      <h2 id="rec-title">{t('posture-recommendation')}</h2>
      {#each findings.filter((f) => f.id === recommendation.id) as finding (finding.id)}
        <FindingRow {finding} />
      {/each}
    </section>
  {/if}

  <details class="how">
    <summary><Icon name="circle-question-mark" size={18} />{t('posture-how-title')}</summary>
    <p>{t('posture-how-intro')}</p>
    <table>
      <caption class="visually-hidden">{t('posture-how-title')}</caption>
      <thead>
        <tr
          ><th scope="col">{t('severity-medium')}</th><th scope="col">{t('posture-how-weight')}</th
          ></tr
        >
      </thead>
      <tbody>
        {#each WEIGHTS as [severity, weight] (severity)}
          <tr><td><SeverityBadge {severity} /></td><td class="mono">{weight}</td></tr>
        {/each}
      </tbody>
    </table>
    <p class="muted">{t('posture-how-na')}</p>
  </details>

  <h2 class="section">{t('posture-checks')}</h2>
  <div class="grid">
    {#each cardsFrom(results) as card (card.id)}
      <section class="card" aria-labelledby="group-{card.id}">
        <h3 id="group-{card.id}">{t(`card-${card.id}`)}</h3>
        <ul>
          {#each card.checks as check (check.id)}
            {@const key = check.id.replace(/[._]/g, '-')}
            <li>
              <span>{t(`${key}-name`)}</span>
              <span class="mono">{t(`outcome-${check.outcome.replace(/_/g, '-')}`)}</span>
            </li>
          {/each}
        </ul>
      </section>
    {/each}
  </div>

  <h2 class="section">{t('posture-open-findings', { count: findings.length })}</h2>
  {#if findings.length === 0}
    <StateMessage kind="empty" />
  {:else}
    <div class="findings">
      {#each findings as finding (finding.id)}
        <FindingRow {finding} />
      {/each}
    </div>
  {/if}
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
  .recommendation {
    display: grid;
    gap: var(--space-3);
    margin-bottom: var(--space-5);
  }
  .recommendation h2 {
    font-size: 20px;
  }
  .how {
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    background: var(--surface);
    padding: var(--space-4);
    margin-bottom: var(--space-5);
  }
  summary {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
    font-weight: 600;
    min-height: var(--target);
  }
  table {
    border-collapse: collapse;
    margin-top: var(--space-3);
  }
  th,
  td {
    padding: var(--space-2) var(--space-4);
    text-align: left;
    border-bottom: 1px solid var(--divider);
  }
  .section {
    margin: var(--space-8) 0 var(--space-4);
    font-size: 20px;
  }
  .grid {
    display: grid;
    gap: var(--space-4);
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
  }
  .card h3 {
    margin-bottom: var(--space-3);
    font-size: 16px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-1);
    font-size: 14px;
    color: var(--text-2);
  }
  li {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
  }
  .findings {
    display: grid;
    gap: var(--space-3);
  }
</style>
