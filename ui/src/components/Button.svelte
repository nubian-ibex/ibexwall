<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    variant = 'secondary',
    disabled = false,
    busy = false,
    onclick,
    children,
  }: {
    variant?: 'primary' | 'secondary' | 'link';
    disabled?: boolean;
    busy?: boolean;
    onclick?: () => void;
    children: Snippet;
  } = $props();
</script>

<button class={variant} type="button" disabled={disabled || busy} aria-busy={busy} {onclick}>
  {@render children()}
</button>

<style>
  button {
    min-height: var(--target);
    padding: 0 var(--space-5);
    border-radius: var(--radius-control);
    border: 1px solid var(--border-strong);
    background: var(--surface);
    font-weight: 600;
    cursor: pointer;
  }
  .primary {
    background: var(--primary);
    border-color: var(--primary);
    color: var(--on-primary);
  }
  .primary:hover:not(:disabled) {
    background: var(--primary-strong);
  }
  .link {
    border-color: transparent;
    background: transparent;
    color: var(--primary);
  }
  button:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
