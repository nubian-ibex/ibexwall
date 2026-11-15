<script lang="ts">
  import { onMount } from 'svelte';
  import Button from './Button.svelte';
  import { t } from '../lib/i18n.svelte';

  // The countdown is announced live: a screen reader hears the deadline
  // once per second, sighted users see it tick. The time left comes from the
  // core's deadline, not from when this component mounted, so a remount or a
  // slow apply cannot show more time than the core will actually give.
  let {
    deadline = null,
    seconds = 60,
    busy = false,
    onkeep,
    oncancel,
    onexpire,
  }: {
    deadline?: string | null;
    /** Used only when the transaction carries no deadline. */
    seconds?: number;
    busy?: boolean;
    onkeep: () => void;
    oncancel: () => void;
    onexpire?: () => void;
  } = $props();

  const mountedAt = Date.now();
  const fallbackEnd = $derived(mountedAt + seconds * 1000);
  const end = $derived.by(() => {
    const parsed = deadline ? Date.parse(deadline) : NaN;
    return Number.isNaN(parsed) ? fallbackEnd : parsed;
  });
  let now = $state(Date.now());
  const remaining = $derived(Math.max(0, Math.ceil((end - now) / 1000)));
  let expired = false;

  $effect(() => {
    if (remaining === 0 && !expired) {
      expired = true;
      onexpire?.();
    }
  });

  onMount(() => {
    const timer = setInterval(() => {
      now = Date.now();
    }, 1000);
    return () => clearInterval(timer);
  });
</script>

<div class="countdown" role="alertdialog" aria-label={t('keep-changes-title')}>
  <p aria-live="polite">{t('keep-changes-prompt', { seconds: remaining })}</p>
  <div class="actions">
    <Button variant="primary" {busy} onclick={onkeep}>{t('keep-changes')}</Button>
    <Button {busy} onclick={oncancel}>{t('undo-changes')}</Button>
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
