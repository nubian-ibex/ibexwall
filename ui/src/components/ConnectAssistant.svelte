<script lang="ts">
  // Connect an AI: which client, what it may do, and (optionally) access from
  // another machine with tokens the person makes. Every change goes through
  // the same reviewed flow as the rest; the screen never applies one itself.
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import {
    CLIENTS,
    PRESETS,
    remoteState,
    remoteUrl,
    snippet,
    type ClientId,
    splitHosts,
    type Preset,
    type RemoteState,
  } from '../lib/assistant';
  import type { NewToken } from '../lib/transport';
  import Button from './Button.svelte';
  import ChangeFlow from './ChangeFlow.svelte';

  let client = $state<ClientId>('claude-code');
  let preset = $state<Preset>('read');
  let remote = $state<RemoteState>({
    enabled: false,
    listen: '127.0.0.1:8765',
    fingerprint: '',
    tokens: [],
  });
  let hosts = $state('');
  let makingCert = $state(false);
  let listen = $state('0.0.0.0:8765');

  let tokenName = $state('');
  let tokenPreset = $state<Preset>('read');
  let tokenExpires = $state('');
  let ownSecret = $state('');
  let made = $state<NewToken | null>(null);
  let makeError = $state(false);
  let revoking = $state<string | null>(null);
  let turning = $state<'on' | 'off' | null>(null);
  let copied = $state(false);

  async function load() {
    const findings = await app.transport.listFindings('system.assistant').catch(() => []);
    remote = remoteState(findings);
    if (remote.enabled) listen = remote.listen;
  }
  load();

  async function make() {
    makeError = false;
    made = null;
    try {
      made = await app.transport.makeAssistantToken({
        name: tokenName.trim(),
        preset: tokenPreset,
        expires: tokenExpires || undefined,
        secret: ownSecret || undefined,
      });
      ownSecret = '';
    } catch {
      makeError = true;
    }
  }

  async function copy(text: string) {
    await navigator.clipboard?.writeText(text);
    copied = true;
  }

  const shown = $derived(snippet(client));
</script>

<section class="card" aria-labelledby="connect-title">
  <h2 id="connect-title">{t('connect-title')}</h2>
  <p class="muted">{t('connect-body')}</p>

  <label class="field">
    <span>{t('connect-client')}</span>
    <select bind:value={client}>
      {#each CLIENTS as id (id)}
        <option value={id}>{t(`connect-client-${id}`)}</option>
      {/each}
    </select>
  </label>
  <p class="muted">{t('connect-paste', { where: shown.where })}</p>
  <pre class="code">{shown.text}</pre>
  <Button onclick={() => copy(shown.text)}
    >{copied ? t('connect-copied') : t('connect-copy')}</Button
  >

  <h3>{t('connect-allow-title')}</h3>
  <p class="muted">{t('connect-allow-body')}</p>
  <label class="field">
    <span>{t('connect-preset')}</span>
    <select bind:value={preset}>
      {#each PRESETS as id (id)}
        <option value={id}>{t(`connect-preset-${id}`)}</option>
      {/each}
    </select>
  </label>
  <p class="muted">{t(`connect-preset-${preset}-body`)}</p>
  {#key `${client}-${preset}`}
    <ChangeFlow plugin="system.assistant" patch={{ action: 'client', client, preset }} />
  {/key}
</section>

<section class="card" aria-labelledby="remote-title">
  <h2 id="remote-title">{t('remote-title')}</h2>
  <p class="muted">{t('remote-body')}</p>
  <p class="state" role="status">
    {remote.enabled ? t('remote-on', { listen: remote.listen }) : t('remote-off')}
  </p>

  <h3>{t('remote-tokens-title')}</h3>
  {#if remote.tokens.length === 0}
    <p class="muted">{t('remote-tokens-none')}</p>
  {:else}
    <ul class="tokens">
      {#each remote.tokens as token (token.id)}
        <li>
          <div>
            <strong>{token.name}</strong>
            <span class="muted">
              {t(`connect-preset-${token.preset}`)} ·
              {token.expires ? t('remote-expires', { day: token.expires }) : t('remote-no-expiry')}
            </span>
          </div>
          <Button onclick={() => (revoking = revoking === token.id ? null : token.id)}
            >{t('remote-revoke')}</Button
          >
          {#if revoking === token.id}
            <div class="flow">
              <p class="muted">{t('remote-revoke-body')}</p>
              {#key token.id}
                <ChangeFlow
                  plugin="system.assistant"
                  patch={{ action: 'token_revoke', id: token.id }}
                />
              {/key}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <h3>{t('remote-new-title')}</h3>
  <div class="row">
    <label class="field">
      <span>{t('remote-new-name')}</span>
      <input type="text" bind:value={tokenName} maxlength="60" autocomplete="off" />
    </label>
    <label class="field">
      <span>{t('connect-preset')}</span>
      <select bind:value={tokenPreset}>
        {#each PRESETS as id (id)}
          <option value={id}>{t(`connect-preset-${id}`)}</option>
        {/each}
      </select>
    </label>
    <label class="field">
      <span>{t('remote-new-expires')}</span>
      <input type="date" bind:value={tokenExpires} />
    </label>
  </div>
  <label class="field">
    <span>{t('remote-new-secret')}</span>
    <input type="password" bind:value={ownSecret} autocomplete="off" spellcheck="false" />
  </label>
  <p class="muted">{t('remote-new-secret-help')}</p>
  <Button variant="primary" onclick={make}>{t('remote-new-make')}</Button>
  {#if makeError}
    <p class="problem" role="alert">{t('remote-new-failed')}</p>
  {/if}

  {#if made}
    <div class="once" role="status">
      <strong>{t('remote-token-once')}</strong>
      <pre class="code">{made.token}</pre>
      <Button onclick={() => copy(made?.token ?? '')}
        >{copied ? t('connect-copied') : t('connect-copy')}</Button
      >
      <p class="muted">{t('remote-token-env')}</p>
      <p>{t('remote-token-review')}</p>
      {#key made.token}
        <ChangeFlow plugin="system.assistant" patch={made.patch} />
      {/key}
    </div>
  {/if}

  <h3>{t('remote-cert-title')}</h3>
  <p class="muted">{t('remote-cert-body')}</p>
  {#if remote.fingerprint}
    <p>{t('remote-cert-fingerprint')}</p>
    <pre class="code">{remote.fingerprint}</pre>
  {/if}
  <label class="field">
    <span>{t('remote-cert-hosts')}</span>
    <input type="text" bind:value={hosts} autocomplete="off" spellcheck="false" />
  </label>
  <p class="muted">{t('remote-cert-hosts-help')}</p>
  <Button onclick={() => (makingCert = !makingCert)}
    >{remote.fingerprint ? t('remote-cert-replace') : t('remote-cert-make')}</Button
  >
  {#if makingCert}
    <p class="muted">{t('remote-cert-never-shown')}</p>
    {#key `${hosts}-${remote.fingerprint}`}
      <ChangeFlow
        plugin="system.assistant"
        patch={{
          action: 'tls',
          hosts: splitHosts(hosts),
          days: 365,
          replace: remote.fingerprint !== '',
        }}
      />
    {/key}
  {/if}

  <h3>{t('remote-switch-title')}</h3>
  <p class="muted">{t('remote-tls')}</p>
  <label class="field">
    <span>{t('remote-listen')}</span>
    <input type="text" bind:value={listen} autocomplete="off" spellcheck="false" />
  </label>
  <p class="muted">{t('remote-listen-help')}</p>
  <div class="actions">
    <Button onclick={() => (turning = turning === 'on' ? null : 'on')}>{t('remote-turn-on')}</Button
    >
    <Button onclick={() => (turning = turning === 'off' ? null : 'off')}
      >{t('remote-turn-off')}</Button
    >
  </div>
  {#if turning}
    {#key `${turning}-${listen}`}
      <ChangeFlow
        plugin="system.assistant"
        patch={turning === 'on'
          ? { action: 'http', enabled: true, listen }
          : { action: 'http', enabled: false }}
      />
    {/key}
  {/if}
  {#if remote.enabled}
    <p class="muted">{t('remote-url', { url: remoteUrl(remote.listen) })}</p>
  {/if}
</section>

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    margin-bottom: var(--space-6);
    display: grid;
    gap: var(--space-3);
  }
  h2 {
    font-size: 18px;
  }
  h3 {
    margin: var(--space-3) 0 0;
    font-size: 15px;
    color: var(--text-2);
  }
  .muted {
    color: var(--muted);
  }
  .field {
    display: grid;
    gap: var(--space-1);
  }
  .row {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    gap: var(--space-4);
  }
  .code {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-3) var(--space-4);
    overflow: auto;
    font-family: var(--mono, monospace);
    font-size: 13px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .tokens {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .tokens li {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: var(--space-3);
    align-items: center;
  }
  .flow {
    grid-column: 1 / -1;
  }
  .once {
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4);
    display: grid;
    gap: var(--space-3);
  }
  .actions {
    display: flex;
    gap: var(--space-3);
  }
  .state {
    font-weight: 600;
  }
  .problem {
    color: var(--danger, #b00020);
  }
</style>
