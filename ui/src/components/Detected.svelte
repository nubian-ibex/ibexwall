<script lang="ts">
  // What a plugin found already on this machine: the facts in plain words,
  // and, when it has one, a suggested change to review. It is information:
  // nothing here is a failure and nothing is applied without the usual
  // review.
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import type { Finding } from '../gen/contracts';
  import Button from './Button.svelte';
  import ChangeFlow from './ChangeFlow.svelte';

  let {
    plugin,
    onuse,
  }: {
    plugin: string;
    /** When given, "Use this" fills the screen's own form instead of opening a review. */
    onuse?: (patch: Record<string, unknown>) => void;
  } = $props();

  let notes = $state<Finding[]>([]);
  let reviewing = $state<string | null>(null);

  $effect(() => {
    void app.transport
      .listFindings(plugin)
      .then((all) => (notes = all.filter((f) => f.id.startsWith('detect.'))))
      .catch(() => (notes = []));
  });

  function patchOf(note: Finding): Record<string, unknown> | null {
    const text = note.args?.patch;
    if (!text) return null;
    try {
      const value: unknown = JSON.parse(text);
      return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }
</script>

{#each notes as note (note.id)}
  {@const patch = patchOf(note)}
  <section class="found" aria-labelledby={`found-${note.id}`}>
    <h2 id={`found-${note.id}`}>{t(note.title_key, note.args)}</h2>
    <p>{t(note.summary_key, note.args)}</p>
    {#if patch}
      {#if onuse}
        <Button onclick={() => onuse(patch)}>{t('detected-use')}</Button>
      {:else}
        <Button onclick={() => (reviewing = reviewing === note.id ? null : note.id)}
          >{t('detected-review')}</Button
        >
        {#if reviewing === note.id}
          <ChangeFlow {plugin} {patch} />
        {/if}
      {/if}
    {/if}
  </section>
{/each}

<style>
  .found {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: var(--radius-card);
    padding: var(--space-4) var(--space-5);
    margin-bottom: var(--space-4);
    display: grid;
    gap: var(--space-2);
  }
  h2 {
    font-size: 16px;
  }
  p {
    color: var(--text-2);
    overflow-wrap: anywhere;
  }
</style>
