<script lang="ts">
  import { t } from '../lib/i18n.svelte';

  let { score, tone }: { score: number | null; tone: 'ok' | 'attention' | 'unknown' } = $props();

  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const filled = $derived(score == null ? 0 : (circumference * score) / 100);
  const label = $derived(score == null ? t('score-none') : t('score-label', { score }));
</script>

<div class="ring {tone}" role="img" aria-label={label}>
  <svg viewBox="0 0 120 120" width="144" height="144" aria-hidden="true">
    <circle class="track" cx="60" cy="60" r={radius} />
    <circle
      class="value"
      cx="60"
      cy="60"
      r={radius}
      stroke-dasharray="{filled} {circumference}"
      transform="rotate(-90 60 60)"
    />
  </svg>
  <div class="text" aria-hidden="true">
    <strong>{score ?? '—'}</strong>
    <span>{t('score-of')}</span>
  </div>
</div>

<style>
  .ring {
    position: relative;
    width: 144px;
    height: 144px;
    flex: none;
  }
  circle {
    fill: none;
    stroke-width: 10;
  }
  .track {
    stroke: var(--divider);
  }
  .value {
    stroke-linecap: round;
    transition: stroke-dasharray 0.4s ease;
  }
  .ok .value {
    stroke: var(--primary);
  }
  .attention .value {
    stroke: var(--warning);
  }
  .unknown .value {
    stroke: var(--border-strong);
  }
  .text {
    position: absolute;
    inset: 0;
    display: grid;
    place-content: center;
    text-align: center;
  }
  strong {
    font-size: 40px;
    line-height: 1;
  }
  span {
    color: var(--muted);
    font-size: 13px;
  }
</style>
