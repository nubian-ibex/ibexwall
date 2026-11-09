<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
</script>

{#if app.changing > 0}
  <div class="banner waiting" role="status">{t('change-waiting')}</div>
{:else if app.notice}
  <div class="banner failed" role="alert">
    <span>{t(app.notice)}</span>
    <button type="button" class="dismiss" onclick={() => app.dismissNotice()}>
      {t('notice-dismiss')}
    </button>
  </div>
{/if}

<style>
  .banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-card);
    border: 1px solid var(--border);
  }

  .waiting {
    background: var(--info-soft);
    color: var(--info);
  }

  .failed {
    background: var(--danger-soft);
    color: var(--danger);
  }

  .dismiss {
    flex: none;
    min-height: var(--target);
  }
</style>
