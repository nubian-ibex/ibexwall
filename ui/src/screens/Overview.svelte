<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { cardsFrom } from '../lib/protections';
  import { counts, overallStatus, topRecommendation } from '../lib/status';
  import { relativeTime } from '../lib/time';
  import Button from '../components/Button.svelte';
  import Icon from '../components/Icon.svelte';
  import ProtectionCard from '../components/ProtectionCard.svelte';
  import ScoreRing from '../components/ScoreRing.svelte';
  import StateMessage from '../components/StateMessage.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';

  const posture = $derived(app.posture);
</script>

<header class="page-head">
  <div>
    <h1>{t('overview-title')}</h1>
    {#if posture.status === 'ready'}
      <p class="muted">
        {posture.data.score == null
          ? t('overview-never-checked')
          : t('overview-last-check', {
              when: relativeTime(posture.data.generated_at, i18n.locale),
            })}
      </p>
    {/if}
  </div>
  <Button busy={app.checking} onclick={() => app.checkNow()}>
    <Icon name="refresh-cw" size={16} />
    {app.checking ? t('overview-checking') : t('overview-check-now')}
  </Button>
</header>

{#if posture.status === 'loading'}
  <StateMessage kind="loading" />
{:else if posture.status === 'error'}
  <StateMessage
    kind={posture.error.kind === 'denied' ? 'denied' : 'error'}
    action={String(posture.error.parameters.action ?? '')}
    onretry={() => app.refresh()}
  />
{:else}
  {@const data = posture.data}
  {@const results = data.results ?? []}
  {@const overall = overallStatus(data)}
  {@const summary = counts(results)}
  {@const tone = overall === 'protected' ? 'ok' : overall === 'attention' ? 'attention' : 'unknown'}
  {@const recommendation = topRecommendation(results)}

  <section class="hero" aria-labelledby="hero-title">
    <ScoreRing score={data.score ?? null} {tone} />
    <div class="hero-text">
      <StatusBadge {tone} label={t(`overview-badge-${overall}`)} />
      <h2 id="hero-title">{t(`overview-status-${overall}`)}</h2>
      <p>
        {overall === 'unknown'
          ? t('overview-summary-unknown')
          : t('overview-summary', {
              passed: summary.passed,
              assessed: summary.assessed,
              failed: summary.failed,
            })}
      </p>
      {#if summary.notAssessed > 0}
        <p class="muted">{t('overview-not-assessed', { count: summary.notAssessed })}</p>
      {/if}
      <div class="actions">
        {#if overall === 'unknown'}
          <Button variant="primary" onclick={() => app.checkNow()}>{t('overview-run-first')}</Button
          >
        {:else if recommendation}
          <Button variant="primary" onclick={() => (app.route = 'posture')}>
            {t('overview-view-recommendation')}
          </Button>
        {/if}
        <Button variant="link" onclick={() => (app.route = 'posture')}>
          {t('overview-view-all')}
        </Button>
      </div>
    </div>
    <ul class="trust" aria-label={t('app-name')}>
      <li><Icon name="lock" size={16} />{t('trust-no-change')}</li>
      <li><Icon name="refresh-cw" size={16} />{t('trust-undo')}</li>
      <li><Icon name="shield-check" size={16} />{t('trust-open')}</li>
      <li><Icon name="hard-drive" size={16} />{t('trust-local')}</li>
    </ul>
  </section>

  {#if results.length > 0}
    <h2 class="section">{t('overview-protections')}</h2>
    <div class="grid">
      {#each cardsFrom(results) as card (card.id)}
        <ProtectionCard {card} />
      {/each}
    </div>
  {/if}
{/if}

<style>
  .page-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--space-4);
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  .muted {
    color: var(--muted);
  }
  .hero {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-8);
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-section);
    padding: var(--space-8);
  }
  .hero-text {
    display: grid;
    gap: var(--space-3);
    justify-items: start;
  }
  h2#hero-title {
    font-size: 26px;
  }
  .actions {
    display: flex;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .trust {
    grid-column: 1 / -1;
    list-style: none;
    margin: 0;
    padding: var(--space-5) 0 0;
    border-top: 1px solid var(--divider);
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3) var(--space-8);
    color: var(--text-2);
    font-size: 14px;
  }
  .trust li {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }
  .section {
    margin: var(--space-10) 0 var(--space-4);
    font-size: 20px;
  }
  .grid {
    display: grid;
    gap: var(--space-4);
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  }
</style>
