<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppDestination, AppEntry } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import {
    canBlock,
    counts,
    displayName,
    filterApps,
    initialOf,
    isNew,
    kindKey,
    unavailableKey,
    type AppFilter,
    type NetMode,
  } from '../lib/apps';
  import { i18n, t } from '../lib/i18n.svelte';
  import { relativeTime } from '../lib/time';
  import { TransportError, type AppsListing } from '../lib/transport';
  import Button from '../components/Button.svelte';
  import ChangeFlow from '../components/ChangeFlow.svelte';
  import StateMessage from '../components/StateMessage.svelte';

  const BLOCK_PLUGIN = 'apps.flatpak-network';
  const POLL_MS = 5000;
  const MODES = ['allow', 'monitor', 'ask', 'block'] as const;

  type Load =
    | { status: 'loading' }
    | { status: 'ready'; data: AppsListing }
    | { status: 'error'; error: TransportError };

  let listing = $state<Load>({ status: 'loading' });
  let query = $state('');
  let filter = $state<AppFilter>('all');
  let selectedKey = $state<string | null>(null);
  let destinations = $state<AppDestination[] | null>(null);
  let blocking = $state(false);
  let blockBusy = $state(false);
  let blockFailure = $state(false);
  let now = $state(new Date());
  let modeFailure = $state<string | null>(null);

  async function load() {
    try {
      listing = { status: 'ready', data: await app.transport.listApps() };
    } catch (error) {
      listing = {
        status: 'error',
        error: error instanceof TransportError ? error : new TransportError('unreachable'),
      };
    }
    now = new Date();
  }

  onMount(() => {
    void load();
    // The monitor keeps counting while the window is open.
    const timer = setInterval(() => void load(), POLL_MS);
    return () => clearInterval(timer);
  });

  const apps = $derived(listing.status === 'ready' ? listing.data.apps : []);
  const monitor = $derived(listing.status === 'ready' ? listing.data.monitor : null);
  const tally = $derived(counts(apps, now));
  const visible = $derived(filterApps(apps, filter, query, now));
  const selected = $derived(apps.find((a) => a.key === selectedKey) ?? null);
  const blockPlugin = $derived(
    app.plugins.status === 'ready'
      ? app.plugins.data.find((p) => p.id === BLOCK_PLUGIN)
      : undefined,
  );

  $effect(() => {
    const key = selectedKey;
    destinations = null;
    blocking = false;
    blockFailure = false;
    if (key === null) return;
    let current = true;
    void app.transport
      .getAppDestinations(key)
      .then((rows) => {
        if (current) destinations = rows;
      })
      .catch(() => {
        if (current) destinations = [];
      });
    return () => {
      current = false;
    };
  });

  async function chooseMode(entry: AppEntry, mode: NetMode) {
    if (entry.mode === mode) return;
    modeFailure = null;
    try {
      await app.transport.setAppMode(entry.key, mode);
      await load();
    } catch {
      modeFailure = entry.key;
    }
  }

  function select(entry: AppEntry) {
    selectedKey = entry.key;
  }

  /** The Flatpak plugin must be on before the core will plan with it. */
  async function startBlock() {
    blockBusy = true;
    blockFailure = false;
    try {
      if (blockPlugin && !blockPlugin.enabled) {
        await app.transport.setPluginEnabled(BLOCK_PLUGIN, true);
        await app.refresh();
      }
      blocking = true;
    } catch {
      blockFailure = true;
    } finally {
      blockBusy = false;
    }
  }

  const filters: AppFilter[] = ['all', 'active', 'new'];
</script>

<header class="page-head">
  <h1>{t('apps-title')}</h1>
  <p class="muted">{t('apps-subtitle')}</p>
</header>

<div class="modes">
  {#each MODES as mode (mode)}
    <div class="mode mode-{mode}">
      <strong>{t(`apps-mode-${mode}`)}</strong>
      <span>{t(`apps-mode-${mode}-body`)}</span>
    </div>
  {/each}
</div>

{#if listing.status === 'loading'}
  <StateMessage kind="loading" />
{:else if listing.status === 'error'}
  <StateMessage
    kind={listing.error.kind === 'denied' ? 'denied' : 'error'}
    action="com.ibexwall.read"
    onretry={load}
  />
{:else}
  {#if monitor && !monitor.running}
    <section class="notice warning" role="status">
      <strong>{t('apps-monitor-off', { reason: monitor.reason ?? '' })}</strong>
      <span>{t('apps-monitor-off-body')}</span>
    </section>
  {:else if monitor?.reason}
    <section class="notice" role="status">
      {t('apps-monitor-limited', { reason: monitor.reason })}
    </section>
  {/if}

  <div class="toolbar">
    <label class="search">
      <span class="visually-hidden">{t('apps-search')}</span>
      <input type="search" placeholder={t('apps-search')} bind:value={query} />
    </label>
    <div class="filters" role="group" aria-label={t('apps-filters')}>
      {#each filters as value (value)}
        <button
          type="button"
          class="chip"
          class:on={filter === value}
          aria-pressed={filter === value}
          onclick={() => (filter = value)}
        >
          {t(`apps-filter-${value}`, { count: tally[value] })}
        </button>
      {/each}
    </div>
  </div>

  {#if apps.length === 0}
    <section class="card">
      <h2>{t('apps-empty-title')}</h2>
      <p class="muted">{t('apps-empty-body')}</p>
    </section>
  {:else}
    <div class="layout">
      <section class="list card" aria-label={t('apps-list-label')}>
        {#if visible.length === 0}
          <p class="muted pad">{t('apps-none-match')}</p>
        {/if}
        <ul>
          {#each visible as entry (entry.key)}
            <li class:current={entry.key === selectedKey}>
              <div class="row">
                <button
                  type="button"
                  class="pick"
                  aria-label={t('apps-select', { app: displayName(entry) })}
                  aria-current={entry.key === selectedKey ? 'true' : undefined}
                  onclick={() => select(entry)}
                >
                  <span class="tile" aria-hidden="true">{initialOf(entry)}</span>
                  <span class="who">
                    <span class="name">
                      {displayName(entry)}
                      <span class="badge">{t(kindKey(entry))}</span>
                      {#if isNew(entry, now)}<span class="badge fresh">{t('apps-new-badge')}</span
                        >{/if}
                    </span>
                    <span class="muted small">
                      {t('apps-summary', {
                        destinations: entry.destinations,
                        connections: entry.connections,
                      })}
                    </span>
                  </span>
                </button>
                <div
                  class="segmented"
                  role="radiogroup"
                  aria-label={t('apps-mode-group', { app: displayName(entry) })}
                >
                  {#each MODES as mode (mode)}
                    {@const why = unavailableKey(entry, monitor, mode)}
                    <button
                      type="button"
                      role="radio"
                      class="seg seg-{mode}"
                      aria-checked={entry.mode === mode}
                      disabled={why !== null}
                      title={why === null ? undefined : t(why)}
                      onclick={() => void chooseMode(entry, mode)}
                    >
                      {t(`apps-mode-${mode}`)}
                    </button>
                  {/each}
                </div>
              </div>
              {#if modeFailure === entry.key}
                <p class="error small pad" role="alert">{t('apps-mode-failed')}</p>
              {/if}
            </li>
          {/each}
        </ul>
      </section>

      <aside class="details card" aria-labelledby="apps-details">
        <h2 id="apps-details">{t('apps-details-title')}</h2>
        {#if selected === null}
          <p class="muted">{t('apps-details-hint')}</p>
        {:else}
          <div class="head">
            <span class="tile big" aria-hidden="true">{initialOf(selected)}</span>
            <div>
              <h3>{displayName(selected)}</h3>
              <span class="badge">{t(kindKey(selected))}</span>
            </div>
          </div>
          <ul class="facts">
            {#if selected.package}<li>{t('apps-package', { name: selected.package })}</li>{/if}
            {#if selected.exe_path}<li class="mono">
                {t('apps-exe', { path: selected.exe_path })}
              </li>{/if}
            <li>
              {t('apps-first-seen', { when: relativeTime(selected.first_seen, i18n.locale) })}
            </li>
            <li>
              {t('apps-last-activity', { when: relativeTime(selected.last_seen, i18n.locale) })}
            </li>
          </ul>

          <h3 class="eyebrow">{t('apps-where')}</h3>
          {#if destinations === null}
            <p class="muted" role="status">{t('state-loading')}</p>
          {:else if destinations.length === 0}
            <p class="muted">{t('apps-no-destinations')}</p>
          {:else}
            <ul class="dests">
              {#each destinations as row (row.destination + ':' + row.port)}
                <li>
                  <span class="mono dest">{row.destination}</span>
                  <span class="muted small">
                    {t('apps-port', { port: row.port })} · {t('apps-times', { count: row.count })}
                    {#if !row.resolved}· {t('apps-no-domain')}{/if}
                  </span>
                </li>
              {/each}
            </ul>
          {/if}

          {#if canBlock(selected)}
            <section class="block" aria-labelledby="apps-block">
              <h3 id="apps-block">{t('apps-block-title')}</h3>
              <p class="muted">{t('apps-block-body')}</p>
              <p class="muted small">{t('apps-block-scope')}</p>
              {#if !blockPlugin}
                <p class="muted">{t('apps-block-unavailable')}</p>
              {:else if !blocking}
                <Button variant="secondary" busy={blockBusy} onclick={startBlock}>
                  {t('apps-block-start')}
                </Button>
                {#if blockFailure}
                  <p class="error" role="alert">{t('apps-block-enable-failed')}</p>
                {/if}
              {:else}
                <ChangeFlow plugin={BLOCK_PLUGIN} patch={{ app: selected.id }} />
              {/if}
            </section>
          {:else}
            <p class="muted small">{t('apps-block-other')}</p>
          {/if}
        {/if}
      </aside>
    </div>
  {/if}
  <p class="muted small privacy">{t('apps-privacy')}</p>
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
    margin: 0 0 var(--space-3);
  }
  h3 {
    font-size: 16px;
    margin: 0;
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
  .modes {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: var(--space-3);
    margin-bottom: var(--space-5);
  }
  .mode {
    display: grid;
    gap: var(--space-1);
    padding: var(--space-4);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    font-size: 14px;
  }
  .mode strong {
    font-size: 16px;
  }
  .mode-allow strong {
    color: var(--primary-strong);
  }
  .mode-monitor strong {
    color: var(--info);
  }
  .mode-ask strong {
    color: var(--warning-text);
  }
  .mode-block strong {
    color: var(--danger);
  }
  .notice {
    display: grid;
    gap: var(--space-1);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
    background: var(--info-soft);
    border-radius: var(--radius-card);
  }
  .notice.warning {
    background: var(--warning-soft);
    border: 1px solid var(--warning-border);
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }
  .search {
    flex: 1 1 260px;
  }
  .search input {
    width: 100%;
    min-height: var(--target);
    padding: 0 var(--space-4);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-control);
    background: var(--surface);
    color: inherit;
    font: inherit;
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .chip {
    min-height: var(--target);
    padding: 0 var(--space-4);
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    background: var(--surface);
    color: inherit;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  .chip.on {
    background: var(--text);
    color: var(--surface);
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1.7fr) minmax(280px, 1fr);
    gap: var(--space-4);
    align-items: start;
  }
  .list {
    padding: 0;
    overflow: hidden;
  }
  .pad {
    padding: var(--space-5);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .list li + li {
    border-top: 1px solid var(--border);
  }
  .list li.current {
    background: var(--primary-soft);
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
  }
  .pick {
    flex: 1 1 220px;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: var(--target);
    padding: 0;
    border: 0;
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }
  .tile {
    flex: none;
    display: grid;
    place-items: center;
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: var(--primary-strong);
    color: var(--surface);
    font-weight: 700;
    font-size: 18px;
  }
  .tile.big {
    width: 56px;
    height: 56px;
    font-size: 22px;
  }
  .who {
    display: grid;
    gap: 2px;
  }
  .name {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    font-weight: 600;
    font-size: 16px;
  }
  .badge {
    padding: 1px var(--space-2);
    border-radius: 6px;
    background: var(--surface-2);
    color: var(--text-2);
    font-size: 12px;
    font-weight: 500;
  }
  .badge.fresh {
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .segmented {
    display: inline-flex;
    padding: 3px;
    border-radius: var(--radius-control);
    background: var(--surface-2);
  }
  .seg {
    min-height: 36px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: 8px;
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .seg[aria-checked='true'] {
    background: var(--surface);
    color: var(--info);
    box-shadow: 0 1px 2px rgb(0 0 0 / 15%);
  }
  .seg:disabled {
    cursor: not-allowed;
    color: var(--muted);
  }
  .details {
    display: grid;
    gap: var(--space-3);
  }
  .head {
    display: flex;
    gap: var(--space-3);
    align-items: center;
  }
  .facts {
    margin: 0;
    display: grid;
    gap: var(--space-1);
    font-size: 14px;
  }
  .facts li {
    margin: 0;
  }
  .eyebrow {
    margin-top: var(--space-2);
    color: var(--muted);
    font-size: 12px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .dests {
    display: grid;
    gap: var(--space-3);
  }
  .dests li {
    display: grid;
    gap: 2px;
    padding-bottom: var(--space-3);
    border-bottom: 1px solid var(--border);
  }
  .dest {
    font-weight: 600;
  }
  .block {
    display: grid;
    gap: var(--space-3);
    margin-top: var(--space-3);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
    justify-items: start;
  }
  .block p {
    margin: 0;
  }
  .error {
    color: var(--danger);
  }
  .privacy {
    margin-top: var(--space-4);
  }
  @media (max-width: 960px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
</style>
