<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { displayName } from '../lib/apps';
  import { t } from '../lib/i18n.svelte';
  import type { PromptScope } from '../lib/transport';
  import Button from './Button.svelte';

  // A connection held in Ask mode: the first one waiting is shown, the rest
  // are counted. Names and destinations come from other programs and the
  // network, so they are only ever displayed as text.
  const current = $derived(app.prompts[0] ?? null);
  const more = $derived(Math.max(0, app.prompts.length - 1));

  let scope = $state<PromptScope>('once');
  let busy = $state(false);
  let failed = $state(false);
  let first = $state<HTMLButtonElement | null>(null);
  let shown = $state<string | null>(null);

  const SCOPES: PromptScope[] = ['once', 'destination', 'always'];

  // A new question starts from the safest scope and puts focus on the
  // decision, so a keyboard user can answer without hunting for it.
  $effect(() => {
    const id = current?.id ?? null;
    if (id !== shown) {
      shown = id;
      scope = 'once';
      failed = false;
      if (id !== null) queueMicrotask(() => first?.focus());
    }
  });

  async function answer(decision: 'allow' | 'block') {
    if (!current) return;
    busy = true;
    failed = false;
    try {
      await app.transport.answerPrompt(current.id, decision, scope);
    } catch {
      failed = true;
    } finally {
      busy = false;
      await app.refreshPrompts();
    }
  }

  const name = $derived(
    current
      ? displayName({
          key: current.app,
          kind: current.kind,
          id: current.app.slice(current.app.indexOf(':') + 1),
          exe_path: current.exe_path ?? null,
          package: null,
          first_seen: current.created,
          last_seen: current.created,
          connections: 0,
          destinations: 0,
          mode: 'ask',
        })
      : '',
  );
</script>

{#if current}
  <div
    class="prompt"
    role="alertdialog"
    aria-labelledby="prompt-title"
    aria-describedby="prompt-body"
  >
    <h2 id="prompt-title">{t('prompt-title', { app: name })}</h2>
    <p id="prompt-body">
      {t('prompt-body', { destination: current.destination, port: current.port })}
    </p>
    {#if current.destination !== current.address}
      <p class="muted small mono">{t('prompt-address', { address: current.address })}</p>
    {/if}
    <fieldset>
      <legend>{t('prompt-scope-label')}</legend>
      {#each SCOPES as value (value)}
        <label>
          <input type="radio" name="prompt-scope" {value} bind:group={scope} />
          {t(`prompt-scope-${value}`)}
        </label>
      {/each}
    </fieldset>
    <div class="actions">
      <button
        type="button"
        class="primary"
        bind:this={first}
        disabled={busy}
        onclick={() => void answer('allow')}
      >
        {t('prompt-allow')}
      </button>
      <Button variant="secondary" {busy} onclick={() => void answer('block')}>
        {t('prompt-block')}
      </Button>
    </div>
    <p class="muted small">{t('prompt-fallback')}</p>
    {#if more > 0}<p class="muted small" role="status">{t('prompt-more', { count: more })}</p>{/if}
    {#if failed}<p class="error small" role="alert">{t('prompt-failed')}</p>{/if}
  </div>
{/if}

<style>
  .prompt {
    position: fixed;
    right: var(--space-5);
    bottom: var(--space-5);
    z-index: 20;
    width: min(380px, calc(100vw - 2 * var(--space-5)));
    padding: var(--space-5);
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-card);
    box-shadow: 0 8px 28px rgb(0 0 0 / 22%);
  }
  h2 {
    font-size: 17px;
    margin: 0 0 var(--space-2);
    overflow-wrap: anywhere;
  }
  p {
    margin: 0 0 var(--space-3);
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--muted);
  }
  .small {
    font-size: 13px;
  }
  .mono {
    font-family: var(--font-mono, monospace);
  }
  .error {
    color: var(--danger, #b00020);
  }
  fieldset {
    border: 0;
    margin: 0 0 var(--space-4);
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  legend {
    font-weight: 600;
    margin-bottom: var(--space-2);
  }
  label {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    min-height: var(--target);
  }
  .actions {
    display: flex;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }
  .primary {
    min-height: var(--target);
    padding: 0 var(--space-5);
    border-radius: var(--radius-control);
    border: 1px solid var(--primary);
    background: var(--primary);
    color: var(--on-primary);
    font-weight: 600;
    cursor: pointer;
  }
  .primary:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
