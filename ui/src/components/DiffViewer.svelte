<script lang="ts">
  import type { OpPreview } from '../gen/contracts';

  let { ops }: { ops: OpPreview[] } = $props();
</script>

<div class="diff" aria-label="Preview of changes">
  {#each ops as op, index (index)}
    <div class="op">
      <span class="target mono">{op.target}</span>
      {#if op.diff}
        <pre><code>{op.diff}</code></pre>
      {:else}
        <span class="plain">{op.op}</span>
      {/if}
    </div>
  {/each}
</div>

<style>
  .diff {
    border: 1px solid var(--border);
    border-radius: var(--radius-control);
    background: var(--surface-2);
    overflow: hidden;
  }
  .op {
    display: grid;
    grid-template-columns: 260px 1fr;
    border-bottom: 1px solid var(--divider);
  }
  .op:last-child {
    border-bottom: none;
  }
  .target {
    padding: var(--space-2) var(--space-3);
    border-right: 1px solid var(--divider);
    overflow-wrap: anywhere;
  }
  pre {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    font-family: var(--font-mono);
    font-size: 13px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .plain {
    padding: var(--space-2) var(--space-3);
    color: var(--muted);
  }
</style>
