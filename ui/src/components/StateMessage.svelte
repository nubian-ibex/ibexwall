<script lang="ts">
  import type { Snippet } from 'svelte';
  import Button from './Button.svelte';
  import { t } from '../lib/i18n.svelte';

  // Empty, loading, error and permission-denied states share one shape.
  let {
    kind,
    action,
    onretry,
    children,
  }: {
    kind: 'loading' | 'empty' | 'error' | 'denied';
    action?: string;
    onretry?: () => void;
    children?: Snippet;
  } = $props();
</script>

<section
  class="state"
  role={kind === 'loading' ? 'status' : kind === 'error' ? 'alert' : undefined}
>
  {#if kind === 'loading'}
    <p aria-live="polite">{t('state-loading')}</p>
  {:else}
    <h2>{t(`state-${kind}-title`)}</h2>
    <p>{t(`state-${kind}-body`, { action: action ?? '' })}</p>
    {@render children?.()}
    {#if (kind === 'error' || kind === 'denied') && onretry}
      <Button onclick={onretry}>{t('state-retry')}</Button>
    {/if}
  {/if}
</section>

<style>
  .state {
    display: grid;
    gap: var(--space-3);
    justify-items: start;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-8);
    max-width: 640px;
  }
  p {
    color: var(--text-2);
  }
</style>
