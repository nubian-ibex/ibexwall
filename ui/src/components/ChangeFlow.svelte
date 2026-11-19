<script lang="ts">
  // A deliberate single action: the button opens the review panel (Review,
  // Apply, Keep) for this plugin and patch. Nothing changes until the
  // person applies there. `ondone` runs when the machine changed (applied,
  // kept or undone), so the screen can read its state again.
  import { onMount } from 'svelte';
  import { changes } from '../lib/changes.svelte';
  import { t } from '../lib/i18n.svelte';
  import Button from './Button.svelte';

  let {
    plugin,
    patch = {},
    label = '',
    ondone,
  }: {
    plugin: string;
    patch?: Record<string, unknown>;
    label?: string;
    ondone?: () => void;
  } = $props();

  onMount(() => (ondone ? changes.onApplied(ondone) : undefined));
</script>

<div class="actions">
  <Button variant="primary" onclick={() => changes.propose(plugin, patch, label)}>
    {t('change-review')}
  </Button>
  <span class="muted">{t('change-review-hint')}</span>
</div>

<style>
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .muted {
    color: var(--muted);
    font-size: 14px;
  }
</style>
