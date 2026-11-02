<script lang="ts">
  import Icon from './Icon.svelte';

  // The label always states the status; colour and icon only reinforce it.
  let { tone, label }: { tone: 'ok' | 'attention' | 'unknown'; label: string } = $props();
  const icon = $derived(
    tone === 'ok' ? 'check' : tone === 'attention' ? 'triangle-alert' : 'circle-question-mark',
  );
</script>

<span class="badge {tone}"><Icon name={icon} size={14} />{label}</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: 2px var(--space-3);
    border-radius: 999px;
    font-size: 13px;
    font-weight: 600;
  }
  .ok {
    background: var(--primary-soft);
    color: var(--primary-strong);
  }
  .attention {
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .unknown {
    background: var(--info-soft);
    color: var(--info);
  }
</style>
