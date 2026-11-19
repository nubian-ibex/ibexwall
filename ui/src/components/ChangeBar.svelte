<script lang="ts">
  // Always in the same place, at the bottom of the content: what is queued,
  // and the one button that starts the review. Hidden when nothing is queued
  // or while the review is open.
  import { changes } from '../lib/changes.svelte';
  import { t } from '../lib/i18n.svelte';
  import Button from './Button.svelte';

  const labels = $derived(
    [...new Set(changes.drafts.map((d) => d.label).filter((l) => l !== ''))].join(', '),
  );
</script>

{#if changes.drafts.length > 0 && changes.panel === null}
  <div class="bar" role="region" aria-label={t('changebar-label')}>
    <div class="inner">
      <span class="count" aria-hidden="true">{changes.total}</span>
      <div class="text">
        <strong>{t('changebar-title', { count: changes.total })}</strong>
        <span>{labels ? `${labels}. ` : ''}{t('changebar-note')}</span>
      </div>
      <Button variant="link" onclick={() => changes.discard()}>{t('changebar-discard')}</Button>
      <Button variant="primary" onclick={() => changes.review()}>{t('changebar-review')}</Button>
    </div>
  </div>
{/if}

<style>
  .bar {
    position: sticky;
    bottom: 0;
    z-index: 20;
    padding: var(--space-3) 0 var(--space-4);
    pointer-events: none;
  }
  .inner {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-3) var(--space-3) var(--space-5);
    background: var(--text);
    color: var(--bg);
    border-radius: var(--radius-section);
    box-shadow: 0 10px 40px rgba(22, 32, 28, 0.25);
  }
  .count {
    flex: none;
    min-width: 32px;
    height: 32px;
    display: grid;
    place-items: center;
    border-radius: 999px;
    background: var(--primary);
    color: var(--on-primary);
    font-weight: 700;
  }
  .text {
    flex: 1;
    min-width: 0;
    display: grid;
  }
  .text span {
    font-size: 13px;
    opacity: 0.8;
  }
  .inner :global(button.link) {
    color: inherit;
  }
</style>
