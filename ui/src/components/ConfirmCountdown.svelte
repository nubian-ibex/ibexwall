<script lang="ts">
  import { onMount } from 'svelte';
  import Button from './Button.svelte';
  import { t } from '../lib/i18n.svelte';

  // The countdown is announced live: a screen reader hears the deadline
  // once per second, sighted users see it tick.
  let { seconds, onkeep, oncancel }: { seconds: number; onkeep: () => void; oncancel: () => void } =
    $props();

  // Seconds already gone; `remaining` derives from it, so a new
  // countdown resets cleanly.
  let elapsed = $state(0);
  const remaining = $derived(Math.max(0, seconds - elapsed));

  onMount(() => {
    const timer = setInterval(() => {
      elapsed += 1;
    }, 1000);
    return () => clearInterval(timer);
  });
</script>

<div class="countdown" role="alertdialog" aria-label={t('keep-changes-title')}>
  <p aria-live="polite">{t('keep-changes-prompt', { seconds: remaining })}</p>
  <div class="actions">
    <Button variant="primary" onclick={onkeep}>{t('keep-changes')}</Button>
    <Button onclick={oncancel}>{t('undo-changes')}</Button>
  </div>
</div>

<style>
  .countdown {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-5);
    background: var(--warning-soft);
    border: 1px solid var(--warning-border);
    border-radius: var(--radius-card);
    color: var(--warning-text);
    font-weight: 500;
  }
  .actions {
    display: flex;
    gap: var(--space-3);
  }
</style>
