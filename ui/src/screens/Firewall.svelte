<script lang="ts">
  import { onMount } from 'svelte';
  import type { FirewallState } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import {
    PROFILES,
    PROTOCOLS,
    canEnableBasic,
    canSwitchProfile,
    format,
    hasServices,
    portSpec,
    profileOf,
    unnamedListening,
    type ProfileId,
  } from '../lib/firewall';
  import { t } from '../lib/i18n.svelte';
  import { TransportError } from '../lib/transport';
  import ChangeFlow from '../components/ChangeFlow.svelte';
  import Detected from '../components/Detected.svelte';
  import StateMessage from '../components/StateMessage.svelte';
  import Switch from '../components/Switch.svelte';

  const PLUGIN = 'net.firewall';

  type Load =
    | { status: 'loading' }
    | { status: 'ready'; data: FirewallState }
    | { status: 'error'; error: TransportError };

  let load = $state<Load>({ status: 'loading' });
  let busy = $state(false);
  let pending = $state<Record<string, unknown> | null>(null);
  let port = $state('');
  let proto = $state<(typeof PROTOCOLS)[number]>('tcp');
  let service = $state('');
  let profile = $state<ProfileId>('public');
  let keepListening = $state(true);
  let portTouched = $state(false);
  let serviceTouched = $state(false);

  async function refresh() {
    try {
      load = { status: 'ready', data: await app.transport.getFirewall() };
    } catch (error) {
      load = {
        status: 'error',
        error: error instanceof TransportError ? error : new TransportError('unreachable'),
      };
    }
  }

  onMount(() => {
    void refresh();
  });

  const fw = $derived(load.status === 'ready' ? load.data : null);
  const plugin = $derived(
    app.plugins.status === 'ready' ? app.plugins.data.find((p) => p.id === PLUGIN) : undefined,
  );
  const controls = $derived(plugin?.enabled === true);
  const portValue = $derived(portSpec(port, proto));
  const serviceValid = $derived(/^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/.test(service.trim()));
  const unnamed = $derived(fw ? unnamedListening(fw) : []);

  $effect(() => {
    // Start the profile choice at the firewall's own zone when it is one.
    if (fw?.zone) profile = profileOf(fw.zone);
  });

  async function toggle(value: boolean) {
    if (!plugin) return;
    busy = true;
    try {
      await app.transport.setPluginEnabled(plugin.id, value);
      await app.refresh();
    } finally {
      busy = false;
    }
  }

  function propose(patch: Record<string, unknown>) {
    pending = patch;
  }

  function addPort() {
    portTouched = true;
    if (portValue) propose({ allow: portValue });
  }

  function addService() {
    serviceTouched = true;
    if (serviceValid) propose({ allow_service: service.trim() });
  }

  const statusKey = $derived(
    fw?.active === true
      ? 'firewall-status-active'
      : fw?.active === false
        ? 'firewall-status-inactive'
        : 'firewall-status-unknown',
  );
</script>

<header class="page-head">
  <h1>{t('firewall-title')}</h1>
  <p class="muted">{t('firewall-subtitle')}</p>
</header>

<Detected plugin="net.firewall" />

{#if load.status === 'loading' || app.plugins.status === 'loading'}
  <StateMessage kind="loading" />
{:else if load.status === 'error'}
  <StateMessage
    kind={load.error.kind === 'denied' ? 'denied' : 'error'}
    action="com.ibexwall.read"
    onretry={refresh}
  />
{:else if fw}
  <section class="card status" aria-labelledby="fw-status">
    <div>
      <h2 id="fw-status">{t(statusKey)}</h2>
      <p class="muted">
        {t('firewall-manager', { manager: t(`firewall-manager-${fw.backend}`) })}
        {#if fw.zone}· {t('firewall-zone', { zone: fw.zone })}{/if}
      </p>
      {#if fw.active !== true}
        <p class="muted">{t('firewall-inactive-body')}</p>
      {/if}
    </div>
    {#if plugin}
      <Switch
        checked={controls}
        label={t(controls ? 'plugins-enabled' : 'plugins-disabled')}
        disabled={busy || plugin.locked}
        onchange={toggle}
      />
    {/if}
  </section>

  {#if !controls}
    <section class="card notice" role="status">
      <h2>{t('firewall-plugin-off-title')}</h2>
      <p class="muted">{t('firewall-plugin-off-body')}</p>
    </section>
  {/if}

  {#if canEnableBasic(fw)}
    <section class="card" aria-labelledby="fw-enable">
      <h2 id="fw-enable">{t('firewall-enable-title')}</h2>
      <p>{t('firewall-enable-body')}</p>
      <label class="check">
        <input type="checkbox" bind:checked={keepListening} />
        <span>{t('firewall-enable-keep')}</span>
      </label>
      <div>
        <button
          type="button"
          class="action"
          disabled={!controls}
          onclick={() => propose({ enable_basic: true, allow_listening: keepListening })}
        >
          {t('firewall-enable-title')}
        </button>
      </div>
    </section>
  {/if}

  <section class="card" aria-labelledby="fw-ports">
    <h2 id="fw-ports">{t('firewall-allowed-ports')}</h2>
    {#if fw.ports.length === 0}
      <p class="muted">{t('firewall-none')}</p>
    {:else}
      <ul class="rows">
        {#each fw.ports as rule (format(rule))}
          <li>
            <span class="mono">{format(rule)}</span>
            <button
              type="button"
              class="link"
              disabled={!controls}
              aria-label={t('firewall-remove', { what: format(rule) })}
              onclick={() => propose({ remove: format(rule) })}
            >
              {t('firewall-remove', { what: format(rule) })}
            </button>
          </li>
        {/each}
      </ul>
    {/if}

    <h3>{t('firewall-add-title')}</h3>
    <div class="form">
      <label class="field">
        <span>{t('firewall-port')}</span>
        <input
          type="text"
          inputmode="numeric"
          bind:value={port}
          aria-invalid={portTouched && !portValue}
          aria-describedby={portTouched && !portValue ? 'port-error' : undefined}
        />
      </label>
      <label class="field">
        <span>{t('firewall-protocol')}</span>
        <select bind:value={proto}>
          {#each PROTOCOLS as value (value)}
            <option {value}>{value.toUpperCase()}</option>
          {/each}
        </select>
      </label>
      <button type="button" class="action" disabled={!controls} onclick={addPort}>
        {t('firewall-allow')}
      </button>
    </div>
    {#if portTouched && !portValue}
      <p id="port-error" class="error" role="alert">{t('firewall-port-invalid')}</p>
    {/if}
  </section>

  {#if hasServices(fw)}
    <section class="card" aria-labelledby="fw-services">
      <h2 id="fw-services">{t('firewall-allowed-services')}</h2>
      {#if fw.services.length === 0}
        <p class="muted">{t('firewall-none')}</p>
      {:else}
        <ul class="rows">
          {#each fw.services as name (name)}
            <li>
              <span class="mono">{name}</span>
              <button
                type="button"
                class="link"
                disabled={!controls}
                aria-label={t('firewall-remove', { what: name })}
                onclick={() => propose({ remove_service: name })}
              >
                {t('firewall-remove', { what: name })}
              </button>
            </li>
          {/each}
        </ul>
      {/if}
      <h3>{t('firewall-service-title')}</h3>
      <div class="form">
        <label class="field">
          <span>{t('firewall-service-name')}</span>
          <input
            type="text"
            bind:value={service}
            aria-invalid={serviceTouched && !serviceValid}
            aria-describedby={serviceTouched && !serviceValid ? 'service-error' : undefined}
          />
        </label>
        <button type="button" class="action" disabled={!controls} onclick={addService}>
          {t('firewall-service-allow')}
        </button>
      </div>
      {#if serviceTouched && !serviceValid}
        <p id="service-error" class="error" role="alert">{t('firewall-service-invalid')}</p>
      {/if}
    </section>
  {/if}

  <section class="card" aria-labelledby="fw-profiles">
    <h2 id="fw-profiles">{t('firewall-profiles-title')}</h2>
    <p class="muted">{t('firewall-profiles-body')}</p>
    {#if canSwitchProfile(fw)}
      <fieldset>
        <legend class="visually-hidden">{t('firewall-profiles-title')}</legend>
        {#each PROFILES as option (option)}
          <label class="option">
            <input type="radio" name="fw-profile" value={option} bind:group={profile} />
            <span>
              <strong>{t(`firewall-profile-${option}`)}</strong>
              <span class="muted">{t(`firewall-profile-${option}-body`)}</span>
            </span>
          </label>
        {/each}
      </fieldset>
      <div>
        <button
          type="button"
          class="action"
          disabled={!controls}
          onclick={() => propose({ profile })}
        >
          {t('firewall-profile-apply', { profile: t(`firewall-profile-${profile}`) })}
        </button>
      </div>
    {:else}
      <p class="muted">{t('firewall-profile-unavailable')}</p>
    {/if}

    {#if fw.networks.length > 0}
      <h3>{t('firewall-networks-title')}</h3>
      <ul class="rows networks">
        {#each fw.networks as network (network.name + network.kind)}
          <li>
            <div>
              <strong>{network.name}</strong>
              <span class="badge">{t(`firewall-kind-${network.kind}`)}</span>
              <div class="muted small">
                {t('firewall-network-suggestion', {
                  profile: t(`firewall-profile-${profileOf(network.recommended)}`),
                })}
              </div>
              {#if network.warning}
                <p class="warning" role="note">{t(network.warning)}</p>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  {#if unnamed.length > 0}
    <section class="card" aria-labelledby="fw-listening">
      <h2 id="fw-listening">{t('firewall-listening-title')}</h2>
      <p class="muted">{t('firewall-listening-body')}</p>
      <ul class="chips">
        {#each unnamed as rule (format(rule))}
          <li class="mono">{format(rule)}</li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if fw.other.length > 0}
    <section class="card" aria-labelledby="fw-other">
      <h2 id="fw-other">{t('firewall-other-title')}</h2>
      <ul class="rows">
        {#each fw.other as line (line)}
          <li class="mono">{line}</li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if pending}
    <section class="card" aria-labelledby="fw-review">
      <h2 id="fw-review">{t('firewall-review-note')}</h2>
      {#key JSON.stringify(pending)}
        <ChangeFlow plugin={PLUGIN} patch={pending} />
      {/key}
    </section>
  {/if}
{/if}

<style>
  .page-head {
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  h2 {
    font-size: 18px;
    margin: 0;
  }
  h3 {
    font-size: 16px;
    margin: var(--space-3) 0 0;
  }
  .muted {
    color: var(--muted);
  }
  .small {
    font-size: 13px;
  }
  .mono {
    font-family: var(--font-mono, ui-monospace, monospace);
    overflow-wrap: anywhere;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  .card {
    display: grid;
    gap: var(--space-3);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    margin-bottom: var(--space-4);
    max-width: 760px;
  }
  .card p {
    margin: 0;
  }
  .status {
    grid-template-columns: 1fr auto;
    align-items: center;
  }
  .notice {
    background: var(--warning-soft);
    border-color: var(--warning-border);
  }
  .rows {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  .rows li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
    min-height: var(--target);
    border-bottom: 1px solid var(--border);
  }
  .networks li {
    align-items: flex-start;
  }
  .chips {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .chips li {
    padding: var(--space-1) var(--space-3);
    border-radius: 999px;
    background: var(--surface-2);
  }
  .form {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    align-items: end;
  }
  .field {
    display: grid;
    gap: var(--space-1);
  }
  .field input,
  .field select {
    min-height: var(--target);
    padding: 0 var(--space-3);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-control);
    background: var(--surface);
    color: inherit;
    font: inherit;
  }
  .field input[aria-invalid='true'] {
    border-color: var(--danger);
  }
  .action,
  .link {
    min-height: var(--target);
    border-radius: var(--radius-control);
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  .action {
    padding: 0 var(--space-5);
    border: 1px solid var(--border-strong);
    background: var(--surface);
    color: inherit;
  }
  .link {
    border: 0;
    background: transparent;
    color: var(--danger);
    padding: 0 var(--space-2);
  }
  .action:disabled,
  .link:disabled {
    cursor: not-allowed;
    color: var(--muted);
  }
  fieldset {
    border: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: var(--space-3);
  }
  .option,
  .check {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-3);
    align-items: start;
    min-height: var(--target);
  }
  .option span {
    display: grid;
  }
  .badge {
    padding: 1px var(--space-2);
    border-radius: 6px;
    background: var(--surface-2);
    color: var(--text-2);
    font-size: 12px;
    margin-left: var(--space-2);
  }
  .warning {
    margin-top: var(--space-1);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-control);
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .error {
    color: var(--danger);
  }
</style>
