<script lang="ts">
  // What the protections that are on need and do not find, in one list:
  // each plugin's own "not installed" note, with the command that installs
  // it on this distribution. IbexWall installs nothing itself.
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import type { Finding } from '../gen/contracts';
  import Button from './Button.svelte';

  const missing = $derived<Finding[]>(
    app.findings.status === 'ready'
      ? app.findings.data.filter((f) => f.id.startsWith('detect.') && f.args?.install)
      : [],
  );
  let copied = $state<string | null>(null);

  async function copy(note: Finding) {
    try {
      await navigator.clipboard.writeText(note.args?.install ?? '');
      copied = `${note.plugin}/${note.id}`;
    } catch {
      copied = null;
    }
  }
</script>

{#if missing.length > 0}
  <section class="card" aria-labelledby="missing-title">
    <h2 id="missing-title">{t('missing-title')}</h2>
    <p class="muted">{t('missing-body')}</p>
    <ul>
      {#each missing as note (`${note.plugin}/${note.id}`)}
        <li>
          <strong>{t(note.title_key, note.args)}</strong>
          <code>{note.args?.install}</code>
          <Button onclick={() => copy(note)}>
            {copied === `${note.plugin}/${note.id}` ? t('missing-copied') : t('missing-copy')}
          </Button>
        </li>
      {/each}
    </ul>
  </section>
{/if}

<style>
  .card {
    display: grid;
    gap: var(--space-3);
    margin-top: var(--space-6);
    padding: var(--space-5);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  h2 {
    font-size: 17px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  li {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: var(--space-1) var(--space-3);
    align-items: center;
  }
  strong {
    grid-column: 1;
  }
  code {
    grid-column: 1;
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }
  li > :global(button) {
    grid-column: 2;
    grid-row: 1 / span 2;
  }
</style>
