<script lang="ts">
  import Icon from './Icon.svelte';
  import { t } from '../lib/i18n.svelte';

  // "Pode afetar" (consequence first) and the restore point note appear
  // together with every change action.
  let { keys, restorePoint }: { keys: string[]; restorePoint?: string } = $props();
</script>

{#if keys.length > 0}
  <aside class="may-affect" aria-label={t('may-affect-label')}>
    <Icon name="triangle-alert" size={18} />
    <div>
      <strong>{t('may-affect-title')}</strong>
      <ul>
        {#each keys as key (key)}
          <li>{t(key)}</li>
        {/each}
      </ul>
    </div>
  </aside>
{/if}
{#if restorePoint}
  <aside class="restore">
    <Icon name="clock" size={18} />
    <span>{t('restore-point-note', { point: restorePoint })}</span>
  </aside>
{/if}

<style>
  aside {
    display: flex;
    gap: var(--space-3);
    padding: var(--space-4);
    border-radius: var(--radius-control);
    font-size: 14px;
  }
  .may-affect {
    background: var(--warning-soft);
    border: 1px solid var(--warning-border);
    color: var(--warning-text);
  }
  .may-affect :global(svg) {
    color: var(--warning);
    flex: none;
    margin-top: 2px;
  }
  .may-affect ul {
    margin: var(--space-1) 0 0;
    padding-left: var(--space-5);
  }
  .restore {
    background: var(--info-soft);
    border: 1px solid var(--border);
    color: var(--text-2);
    align-items: center;
  }
  .restore :global(svg) {
    color: var(--info);
    flex: none;
  }
</style>
