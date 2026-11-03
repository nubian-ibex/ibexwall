<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppEntry, Prompt } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import { displayName, initialOf, kindKey } from '../lib/apps';
  import { t } from '../lib/i18n.svelte';
  import type { PromptScope } from '../lib/transport';

  // A connection held in Ask mode (mockup 05): the first one waiting is
  // shown, the rest are counted. Names and destinations come from other
  // programs and the network, so they are only ever displayed as text.
  // `standalone` is the prompt window; otherwise the card floats over the
  // main window.
  let { standalone = false }: { standalone?: boolean } = $props();

  const current = $derived(app.prompts[0] ?? null);
  const more = $derived(Math.max(0, app.prompts.length - 1));

  let scope = $state<PromptScope>('once');
  let busy = $state(false);
  let failed = $state(false);
  let first = $state<HTMLButtonElement | null>(null);
  let shown = $state<string | null>(null);
  let now = $state(Date.now());

  // The scopes in the mockup's order. The default is the narrowest one: a
  // slip of the mouse must not become a permanent rule.
  const SCOPES: PromptScope[] = ['always', 'destination', 'once'];

  onMount(() => {
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

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

  function asEntry(prompt: Prompt): AppEntry {
    return {
      key: prompt.app,
      kind: prompt.kind,
      id: prompt.app.slice(prompt.app.indexOf(':') + 1),
      exe_path: prompt.exe_path ?? null,
      package: null,
      first_seen: prompt.created,
      last_seen: prompt.created,
      connections: 0,
      destinations: 0,
      mode: 'ask',
    };
  }

  const entry = $derived(current ? asEntry(current) : null);
  const seconds = $derived(
    current ? Math.max(0, Math.ceil((Date.parse(current.expires) - now) / 1000)) : 0,
  );
</script>

{#if current && entry}
  <div
    class="prompt"
    class:standalone
    role="alertdialog"
    aria-labelledby="prompt-title"
    aria-describedby="prompt-body"
  >
    {#if standalone}
      <p class="brand">IbexWall</p>
    {/if}
    <div class="head">
      <span class="tile" aria-hidden="true">{initialOf(entry)}</span>
      <div>
        <h2 id="prompt-title">{t('prompt-title', { app: displayName(entry) })}</h2>
        <p class="muted">{t(kindKey(entry))}</p>
      </div>
    </div>
    <dl id="prompt-body" class="facts">
      <dt>{t('prompt-destination')}</dt>
      <dd class="mono">{current.destination}:{current.port}</dd>
      {#if current.destination !== current.address}
        <dt>{t('prompt-address')}</dt>
        <dd class="mono">{current.address}</dd>
      {/if}
      {#if current.exe_path}
        <dt>{t('prompt-program')}</dt>
        <dd class="mono">{current.exe_path}</dd>
      {/if}
    </dl>
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
      <button type="button" class="block" disabled={busy} onclick={() => void answer('block')}>
        {t('prompt-block')}
      </button>
      <button
        type="button"
        class="allow"
        bind:this={first}
        disabled={busy}
        onclick={() => void answer('allow')}
      >
        {t('prompt-allow')}
      </button>
    </div>
    <p class="muted small center" role="timer" aria-live="off">
      {t('prompt-countdown', { seconds })}
    </p>
    {#if more > 0}<p class="muted small center" role="status">
        {t('prompt-more', { count: more })}
      </p>{/if}
    {#if failed}<p class="error small center" role="alert">{t('prompt-failed')}</p>{/if}
  </div>
{/if}

<style>
  .prompt {
    position: fixed;
    right: var(--space-5);
    bottom: var(--space-5);
    z-index: 20;
    width: min(400px, calc(100vw - 2 * var(--space-5)));
    padding: var(--space-5);
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-card);
    box-shadow: 0 8px 28px rgb(0 0 0 / 22%);
  }
  .prompt.standalone {
    position: static;
    width: auto;
    min-height: 100vh;
    border: 0;
    border-radius: 0;
    box-shadow: none;
  }
  .brand {
    margin: 0 0 var(--space-4);
    font-weight: 700;
    color: var(--primary-strong);
  }
  .head {
    display: flex;
    gap: var(--space-4);
    align-items: center;
    margin-bottom: var(--space-4);
  }
  .tile {
    flex: none;
    display: grid;
    place-items: center;
    width: 56px;
    height: 56px;
    border-radius: 14px;
    background: var(--primary-strong);
    color: var(--surface);
    font-weight: 700;
    font-size: 24px;
  }
  h2 {
    font-size: 18px;
    margin: 0;
    overflow-wrap: anywhere;
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .muted {
    color: var(--muted);
  }
  .small {
    font-size: 13px;
  }
  .center {
    text-align: center;
    margin-top: var(--space-3);
  }
  .mono {
    font-family: var(--font-mono, monospace);
  }
  .error {
    color: var(--danger);
  }
  .facts {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0 0 var(--space-4);
    padding: var(--space-4);
    background: var(--surface-2);
    border-radius: var(--radius-control);
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    text-align: right;
    overflow-wrap: anywhere;
  }
  fieldset {
    border: 0;
    margin: 0 0 var(--space-4);
    padding: 0;
    display: grid;
    gap: var(--space-1);
  }
  legend {
    font-weight: 600;
    margin-bottom: var(--space-2);
  }
  label {
    display: flex;
    gap: var(--space-3);
    align-items: center;
    min-height: var(--target);
  }
  .actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-3);
  }
  .actions button {
    min-height: calc(var(--target) + 8px);
    border-radius: var(--radius-control);
    font-weight: 700;
    cursor: pointer;
  }
  .block {
    background: var(--surface);
    border: 1px solid var(--border-strong);
    color: var(--danger);
  }
  .allow {
    background: var(--primary);
    border: 1px solid var(--primary);
    color: var(--on-primary);
  }
  .actions button:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
