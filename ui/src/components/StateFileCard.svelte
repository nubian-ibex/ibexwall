<!-- Export and import of IbexWall's own settings (ADR-0049). -->
<script lang="ts">
  import type { ImportSummary } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import { changeErrorKey, TransportError } from '../lib/transport';
  import Button from './Button.svelte';

  /** An export is a few kilobytes; anything near this is some other file. */
  const MAX_BYTES = 1_000_000;

  let busy = $state(false);
  let saved = $state<string | null>(null);
  let done = $state(false);
  let error = $state<string | null>(null);
  /** The chosen file and what importing it would change. */
  let chosen = $state<{ text: string; summary: ImportSummary } | null>(null);
  const empty = $derived(
    chosen !== null && chosen.summary.settings.length + chosen.summary.plugins.length === 0,
  );

  function explain(reason: unknown): string {
    if (reason instanceof TransportError && reason.code.endsWith('.InvalidArgument')) {
      return t('settings-backup-invalid', { reason: String(reason.parameters['reason'] ?? '') });
    }
    return t(changeErrorKey(reason));
  }

  async function run(work: () => Promise<void>) {
    if (busy) return;
    busy = true;
    error = null;
    saved = null;
    done = false;
    try {
      await app.waiting(work);
    } catch (reason) {
      error = explain(reason);
    } finally {
      busy = false;
    }
  }

  function exportFile() {
    return run(async () => {
      saved = await app.transport.exportState();
    });
  }

  async function onFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    // So that choosing the same file again is noticed.
    input.value = '';
    if (!file) return;
    chosen = null;
    await run(async () => {
      if (file.size > MAX_BYTES) {
        error = t('settings-backup-too-large');
        return;
      }
      const text = await file.text();
      chosen = { text, summary: await app.transport.previewImport(text) };
    });
  }

  function importFile() {
    const file = chosen;
    if (!file) return;
    return run(async () => {
      await app.transport.applyImport(file.text);
      chosen = null;
      done = true;
      await app.refresh();
    });
  }
</script>

<section class="card" aria-labelledby="backup-title">
  <h2 id="backup-title">{t('settings-backup-title')}</h2>
  <p class="muted">{t('settings-backup-body')}</p>
  <div>
    <Button disabled={busy} onclick={exportFile}>{t('settings-backup-export')}</Button>
  </div>
  <label>
    <span>{t('settings-backup-choose')}</span>
    <input type="file" accept=".json,application/json" disabled={busy} onchange={onFile} />
  </label>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if saved}<p role="status">{t('settings-backup-saved', { path: saved })}</p>{/if}
  {#if done}<p role="status">{t('settings-backup-done')}</p>{/if}
  {#if chosen}
    <div class="preview" role="group" aria-label={t('settings-backup-preview')}>
      {#if empty}
        <p>{t('settings-backup-same')}</p>
      {:else}
        <strong>{t('settings-backup-preview')}</strong>
      {/if}
      <ul>
        {#each chosen.summary.settings as row (`${row.plugin} ${row.key}`)}
          <li>{t('settings-backup-setting', { plugin: row.plugin, key: row.key })}</li>
        {/each}
        {#each chosen.summary.plugins as row (row.id)}
          <li>
            {t(row.enabled ? 'settings-backup-plugin-on' : 'settings-backup-plugin-off', {
              plugin: row.id,
            })}
          </li>
        {/each}
        {#each chosen.summary.locked as key (key)}
          <li class="muted">{t('settings-backup-locked', { key })}</li>
        {/each}
      </ul>
      <div class="actions">
        <Button disabled={busy} onclick={() => (chosen = null)}>{t('panel-close')}</Button>
        {#if !empty}
          <Button variant="primary" disabled={busy} onclick={importFile}>
            {t('settings-backup-import')}
          </Button>
        {/if}
      </div>
    </div>
  {/if}
</section>

<style>
  .card {
    display: grid;
    gap: var(--space-4);
    max-width: 480px;
    padding: var(--space-6);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  p {
    margin: 0;
  }
  label {
    display: grid;
    gap: var(--space-2);
    font-weight: 600;
  }
  .error {
    color: var(--danger-strong);
  }
  .preview {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--warning-border);
    background: var(--warning-soft);
    border-radius: var(--radius-control);
    overflow-wrap: anywhere;
  }
  ul {
    margin: 0;
    padding-left: var(--space-5);
  }
  .actions {
    display: flex;
    gap: var(--space-3);
  }
</style>
