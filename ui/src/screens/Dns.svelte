<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import {
    DNS_DEFAULTS,
    DNS_LISTS,
    DNS_PROVIDERS,
    dnsPatch,
    transportFor,
    type DnsChoice,
    type DnsProviderId,
    type DnsTransport,
  } from '../lib/dns';
  import ChangeFlow from '../components/ChangeFlow.svelte';
  import { relativeTime } from '../lib/time';
  import StateMessage from '../components/StateMessage.svelte';
  import type { DnsStatus } from '../gen/contracts';
  import Switch from '../components/Switch.svelte';

  let choice = $state<DnsChoice>({ ...DNS_DEFAULTS });
  let busy = $state(false);
  let counters = $state<DnsStatus | null>(null);

  $effect(() => {
    if (plugin?.enabled) void app.transport.getDnsStatus().then((value) => (counters = value));
    else counters = null;
  });

  const plugin = $derived(
    app.plugins.status === 'ready' ? app.plugins.data.find((p) => p.id === 'net.dns') : undefined,
  );
  const outcome = $derived.by(() => {
    if (!plugin?.enabled) return 'off';
    if (app.posture.status !== 'ready') return 'unknown';
    const result = app.posture.data.results?.find((r) => r.id === 'dns.secure_resolver');
    return result?.outcome ?? 'unknown';
  });
  const transports = $derived(
    DNS_PROVIDERS.find((p) => p.id === choice.provider)?.transports ?? ['tls'],
  );

  function pickProvider(id: DnsProviderId) {
    choice.provider = id;
    choice.transport = transportFor(id, choice.transport);
  }

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
</script>

<header class="page-head">
  <div>
    <h1>{t('dns-title')}</h1>
    <p class="muted">{t('dns-subtitle')}</p>
  </div>
</header>

{#if app.plugins.status === 'loading'}
  <StateMessage kind="loading" />
{:else if app.plugins.status === 'error'}
  <StateMessage kind="error" onretry={() => app.refresh()} />
{:else if !plugin}
  <section class="card">
    <h2>{t('dns-unavailable-title')}</h2>
    <p>{t('dns-unavailable-body')}</p>
  </section>
{:else}
  <section class="card status" aria-labelledby="dns-status">
    <div>
      <h2 id="dns-status">{t(`dns-status-${outcome}`)}</h2>
      <p class="muted">{t(`dns-status-${outcome}-body`)}</p>
    </div>
    <Switch
      checked={plugin.enabled}
      label={t(plugin.enabled ? 'plugins-enabled' : 'plugins-disabled')}
      disabled={busy || plugin.locked}
      onchange={toggle}
    />
  </section>

  <section class="card">
    <fieldset>
      <legend>{t('dns-provider')}</legend>
      {#each DNS_PROVIDERS as provider (provider.id)}
        <label class="option">
          <input
            type="radio"
            name="dns-provider"
            value={provider.id}
            checked={choice.provider === provider.id}
            onchange={() => pickProvider(provider.id)}
          />
          <span>
            <strong>{t(`dns-provider-${provider.id}`)}</strong>
            <span class="muted">
              {t('dns-jurisdiction', { code: provider.jurisdiction })} · {t(
                `dns-provider-${provider.id}-logs`,
              )}
            </span>
          </span>
        </label>
      {/each}
    </fieldset>

    <label class="field">
      <span>{t('dns-transport')}</span>
      <select bind:value={choice.transport}>
        {#each transports as transport (transport)}
          <option value={transport as DnsTransport}>{t(`dns-transport-${transport}`)}</option>
        {/each}
      </select>
    </label>

    <label class="field">
      <span>{t('dns-list')}</span>
      <select bind:value={choice.list}>
        <option value="none">{t('dns-list-none')}</option>
        {#each DNS_LISTS as list (list)}
          <option value={list}>{t(`dns-list-${list}`)}</option>
        {/each}
      </select>
    </label>

    <label class="check">
      <input type="checkbox" bind:checked={choice.enforcement} />
      <span>
        <strong>{t('dns-enforcement')}</strong>
        <span class="muted">{t('dns-enforcement-body')}</span>
      </span>
    </label>
    <label class="check">
      <input type="checkbox" bind:checked={choice.blockDoh} />
      <span>
        <strong>{t('dns-block-doh')}</strong>
        <span class="muted">{t('dns-block-doh-body')}</span>
      </span>
    </label>
    <label class="check">
      <input type="checkbox" bind:checked={choice.browserPolicies} />
      <span>
        <strong>{t('dns-browser-policy')}</strong>
        <span class="muted">{t('dns-browser-policy-body')}</span>
      </span>
    </label>
  </section>

  {#if counters}
    <section class="card" aria-labelledby="dns-counters">
      <h2 id="dns-counters">{t('dns-counters-title')}</h2>
      {#if counters.running}
        <dl>
          <div>
            <dt>{t('dns-counter-blocked-list')}</dt>
            <dd>{counters.blocked_list}</dd>
          </div>
          <div>
            <dt>{t('dns-counter-blocked-doh')}</dt>
            <dd>{counters.blocked_doh}</dd>
          </div>
          <div>
            <dt>{t('dns-counter-forwarded')}</dt>
            <dd>{counters.forwarded}</dd>
          </div>
          <div>
            <dt>{t('dns-counter-errors')}</dt>
            <dd>{counters.upstream_errors}</dd>
          </div>
        </dl>
        <p class="muted">
          {t('dns-counters-updated', { when: relativeTime(counters.updated_at) })}
        </p>
      {:else}
        <p class="muted">{t('dns-counters-not-running')}</p>
      {/if}
      <p class="muted">{t('dns-counters-privacy')}</p>
    </section>
  {/if}

  <section class="card">
    <p class="muted">{t('dns-review-note')}</p>
    <ChangeFlow plugin="net.dns" patch={dnsPatch(choice)} />
  </section>
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
  }
  .muted {
    color: var(--muted);
  }
  .card {
    display: grid;
    gap: var(--space-4);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    margin-bottom: var(--space-4);
    max-width: 760px;
  }
  .status {
    grid-template-columns: 1fr auto;
    align-items: center;
  }
  dl {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: var(--space-3);
  }
  dl div {
    display: grid;
    gap: var(--space-1);
  }
  dt {
    color: var(--muted);
    font-size: 13px;
  }
  dd {
    margin: 0;
    font-size: 22px;
    font-weight: 600;
  }
  fieldset {
    border: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: var(--space-3);
  }
  legend {
    font-weight: 600;
    margin-bottom: var(--space-2);
  }
  .option,
  .check {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: var(--space-3);
    align-items: start;
    min-height: var(--target);
  }
  .option span,
  .check span {
    display: grid;
    gap: var(--space-1);
  }
  input[type='radio'],
  input[type='checkbox'] {
    width: 20px;
    height: 20px;
    margin-top: 2px;
    accent-color: var(--primary);
  }
  .field {
    display: grid;
    gap: var(--space-2);
    font-weight: 600;
  }
  select {
    min-height: var(--target);
    padding: 0 var(--space-3);
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-control);
  }
</style>
