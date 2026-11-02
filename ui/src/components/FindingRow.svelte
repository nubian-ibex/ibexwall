<script lang="ts">
  import type { Finding } from '../gen/contracts';
  import { t } from '../lib/i18n.svelte';
  import SeverityBadge from './SeverityBadge.svelte';

  // Finding text comes from Fluent keys with named args. Untrusted args
  // (domains, ports, process names) are formatted as plain text by
  // Fluent; nothing here ever renders markup.
  let { finding }: { finding: Finding } = $props();
</script>

<article class="finding">
  <header>
    <SeverityBadge severity={finding.severity} />
    <h4>{t(finding.title_key, finding.args)}</h4>
  </header>
  <p>{t(finding.summary_key, finding.args)}</p>
  <div class="meta">
    {#each finding.references as ref (`${ref.framework}:${ref.id}`)}
      <span class="mono">{ref.framework} · {ref.id}</span>
    {/each}
  </div>
</article>

<style>
  .finding {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-4);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
  h4 {
    font-size: 16px;
  }
  p {
    color: var(--text-2);
  }
  .meta {
    display: flex;
    gap: var(--space-4);
    flex-wrap: wrap;
  }
</style>
