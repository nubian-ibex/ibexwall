<script lang="ts">
  // Recommended settings from published hardening guides, each with its
  // source, what it can break and whether this machine already has it. The
  // person ticks what they want and reviews one change per plugin; nothing
  // is applied before they say so, and everything can be undone.
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { docsUrl } from '../lib/site';
  import {
    AREAS,
    CATALOG,
    groupByPlugin,
    statusOf,
    type Item,
    type Status,
  } from '../lib/hardening';
  import { changes } from '../lib/changes.svelte';
  import { onMount } from 'svelte';

  let statuses = $state<Map<string, Status>>(new Map());
  let loaded = $state(false);
  let ticked = $state<string[]>([]);
  let initial = false;

  async function load() {
    const findings = await app.transport.listFindings('system.hardening').catch(() => []);
    statuses = statusOf(findings);
    loaded = true;
    if (!initial) {
      // Only what is safe and still missing starts ticked.
      ticked = CATALOG.items
        .filter((i) => i.recommended && statuses.get(i.id) === 'open')
        .map((i) => i.id);
      initial = true;
    } else {
      // Whatever got applied is no longer something to tick.
      ticked = ticked.filter((id) => statuses.get(id) !== 'applied');
    }
  }
  load();

  const text = (value: { en: string } & Record<string, string>) => value[i18n.locale] ?? value.en;
  const chosen = $derived(CATALOG.items.filter((i) => ticked.includes(i.id)));
  const applied = $derived([...statuses.values()].filter((s) => s === 'applied').length);
  /** What is already in place: one collapsible section, so the screen shows
   * the work there is left to do. */
  const appliedItems = $derived(CATALOG.items.filter((i) => statuses.get(i.id) === 'applied'));

  function toggle(item: Item, on: boolean) {
    const rest = ticked.filter((id) => id !== item.id);
    ticked = on ? [...rest, item.id] : rest;
  }

  // What is ticked is queued in the change bar, one draft per plugin; the
  // review panel plans and applies it. Whatever got applied or undone is
  // read again, so the ticks and the queue follow the machine.
  $effect(() => {
    changes.setSource(
      'hardening',
      groupByPlugin(chosen).map((group) => ({
        id: `hardening-${group.plugin}`,
        plugin: group.plugin,
        patch: group.patch,
        count: chosen.filter((i) => i.apply.plugin === group.plugin).length,
        label: t('nav-hardening'),
      })),
    );
  });
  onMount(() => {
    const stop = changes.onApplied(() => void load());
    return () => {
      stop();
      changes.discard('hardening');
    };
  });
</script>

<header class="page-head">
  <div>
    <h1>{t('hardening-title')}</h1>
    <p class="muted">{t('hardening-subtitle')}</p>
  </div>
</header>

{#if loaded}
  <p class="count" role="status">
    {t('hardening-count', { applied, total: CATALOG.items.length })}
  </p>
{/if}

{#each AREAS as area (area)}
  {@const items = CATALOG.items.filter((i) => i.area === area && statuses.get(i.id) !== 'applied')}
  {#if items.length > 0}
    <section class="area" aria-labelledby={`area-${area}`}>
      <h2 id={`area-${area}`}>{t(`hardening-area-${area}`)}</h2>
      <ul>
        {#each items as item (item.id)}
          {@const status = statuses.get(item.id) ?? 'unknown'}
          {@const link = docsUrl(item.doc)}
          <li class="item">
            <label class="tick">
              <input
                type="checkbox"
                checked={ticked.includes(item.id)}
                onchange={(e) => toggle(item, e.currentTarget.checked)}
              />
              <span class="title">{text(item.title)}</span>
            </label>
            <span class="badges">
              <span class={`badge status-${status}`}>{t(`hardening-status-${status}`)}</span>
              <span class={`badge risk-${item.risk}`}>{t(`hardening-risk-${item.risk}`)}</span>
            </span>
            <p class="summary">{text(item.summary)}</p>
            {#if item.breaks}
              <p class="breaks"><strong>{t('hardening-breaks')}</strong> {text(item.breaks)}</p>
            {/if}
            <p class="sources">
              {t('hardening-sources')}
              {#each item.sources as source, n (source.url + source.section)}
                <a href={source.url} target="_blank" rel="noopener noreferrer"
                  >{source.name}, {source.section}</a
                >{n < item.sources.length - 1 ? '; ' : ''}
              {/each}
              {#if link}
                · <a href={link} target="_blank" rel="noopener noreferrer">{t('hardening-more')}</a>
              {/if}
            </p>
          </li>
        {/each}
      </ul>
    </section>
  {/if}
{/each}

{#if appliedItems.length > 0}
  <details class="applied" aria-labelledby="applied-title">
    <summary id="applied-title"
      >{t('hardening-applied-summary', { count: appliedItems.length })}</summary
    >
    <ul>
      {#each appliedItems as item (item.id)}
        <li class="item done">
          <label class="tick">
            <input type="checkbox" disabled />
            <span class="title">{text(item.title)}</span>
          </label>
          <span class="badges">
            <span class="badge status-applied">{t('hardening-status-applied')}</span>
            <span class={`badge risk-${item.risk}`}>{t(`hardening-risk-${item.risk}`)}</span>
          </span>
          <p class="summary">{text(item.summary)}</p>
          {#if item.breaks}
            <p class="breaks"><strong>{t('hardening-breaks')}</strong> {text(item.breaks)}</p>
          {/if}
          <p class="sources">
            {t('hardening-sources')}
            {#each item.sources as source, n (source.url + source.section)}
              <a href={source.url} target="_blank" rel="noopener noreferrer"
                >{source.name}, {source.section}</a
              >{n < item.sources.length - 1 ? '; ' : ''}
            {/each}
            ·
            <a href={docsUrl(item.doc)} target="_blank" rel="noopener noreferrer"
              >{t('hardening-more')}</a
            >
          </p>
        </li>
      {/each}
    </ul>
  </details>
{/if}

<style>
  .muted {
    color: var(--muted);
  }
  .count {
    margin: var(--space-3) 0 var(--space-5);
    font-weight: 600;
  }
  .area {
    margin-bottom: var(--space-6);
  }
  .applied {
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    background: var(--surface);
    padding: var(--space-4) var(--space-5);
  }
  .applied summary {
    font-weight: 600;
    min-height: var(--target);
    display: flex;
    align-items: center;
    cursor: pointer;
  }
  .applied ul {
    list-style: none;
    margin: var(--space-3) 0 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .area h2 {
    font-size: 18px;
    margin-bottom: var(--space-3);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .item {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4) var(--space-5);
    display: grid;
    grid-template-columns: 1fr auto;
    gap: var(--space-2) var(--space-4);
  }
  .item.done {
    opacity: 0.8;
  }
  .tick {
    display: flex;
    gap: var(--space-3);
    align-items: center;
    min-height: var(--target);
  }
  .title {
    font-weight: 600;
  }
  .badges {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }
  .badge {
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 13px;
    white-space: nowrap;
  }
  .summary,
  .breaks,
  .sources {
    grid-column: 1 / -1;
    color: var(--text-2);
  }
  .sources {
    font-size: 14px;
    overflow-wrap: anywhere;
  }
</style>
