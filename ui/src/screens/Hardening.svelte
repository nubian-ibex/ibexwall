<script lang="ts">
  // Recommended settings from published hardening guides, each with its
  // source, what it can break and whether this machine already has it. The
  // person ticks what they want and reviews one change per plugin; nothing
  // is applied before they say so, and everything can be undone.
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { docsUrl } from '../lib/site';
  import { AREAS, CATALOG, statusOf, type Item, type Status } from '../lib/hardening';
  import HardeningFlow from '../components/HardeningFlow.svelte';

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

  function toggle(item: Item, on: boolean) {
    const rest = ticked.filter((id) => id !== item.id);
    ticked = on ? [...rest, item.id] : rest;
  }

  /** Checks a tick: a risky item states what it can break in the review too. */
  const riskyChosen = $derived(chosen.filter((i) => i.risk !== 'low'));
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
  {@const items = CATALOG.items.filter((i) => i.area === area)}
  {#if items.length > 0}
    <section class="area" aria-labelledby={`area-${area}`}>
      <h2 id={`area-${area}`}>{t(`hardening-area-${area}`)}</h2>
      <ul>
        {#each items as item (item.id)}
          {@const status = statuses.get(item.id) ?? 'unknown'}
          {@const link = docsUrl(item.doc)}
          <li class="item" class:done={status === 'applied'}>
            <label class="tick">
              <input
                type="checkbox"
                checked={ticked.includes(item.id)}
                disabled={status === 'applied'}
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

<section class="review" aria-labelledby="review-title">
  <h2 id="review-title">{t('hardening-review-title', { count: chosen.length })}</h2>
  {#if riskyChosen.length > 0}
    <p class="warn" role="note">{t('hardening-risky', { count: riskyChosen.length })}</p>
  {/if}
  {#key [...ticked].sort().join(',')}
    <HardeningFlow items={chosen} ondone={load} />
  {/key}
</section>

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
  .review {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    margin-top: var(--space-6);
  }
  .warn {
    border-left: 4px solid var(--accent);
    padding: var(--space-2) var(--space-4);
    margin: var(--space-3) 0;
  }
</style>
