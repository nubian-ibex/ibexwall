<script lang="ts">
  import type { Card } from '../lib/protections';
  import { t } from '../lib/i18n.svelte';
  import Icon from './Icon.svelte';
  import StatusBadge from './StatusBadge.svelte';

  let { card }: { card: Card } = $props();
  const stateKey = $derived(`card-state-${card.state}`);
</script>

<article class="card {card.state}" aria-labelledby="card-{card.id}">
  <header>
    <span class="icon"><Icon name={card.icon} size={22} /></span>
    <StatusBadge tone={card.state} label={t(stateKey)} />
  </header>
  <h3 id="card-{card.id}">{t(`card-${card.id}`)}</h3>
  <ul>
    {#each card.checks as check (check.id)}
      <li>
        <span>{t(`${check.id.replace(/[._]/g, '-')}-name`)}</span>
        <span class="mono">{t(`outcome-${check.outcome.replace(/_/g, '-')}`)}</span>
      </li>
    {/each}
  </ul>
</article>

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
    display: grid;
    gap: var(--space-3);
    align-content: start;
  }
  .card.attention {
    border-color: var(--warning-border);
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .icon {
    display: grid;
    place-items: center;
    width: 40px;
    height: 40px;
    border-radius: var(--radius-control);
    background: var(--primary-soft);
    color: var(--primary-strong);
  }
  .attention .icon {
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  h3 {
    font-size: 18px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-1);
    color: var(--text-2);
    font-size: 14px;
  }
  li {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
  }
</style>
