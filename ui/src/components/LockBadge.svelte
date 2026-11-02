<script lang="ts">
  import { t } from '../lib/i18n.svelte';
  import Icon from './Icon.svelte';
</script>

<span class="lock"><Icon name="lock" size={14} />{t('plugins-locked')}</span>

<style>
  .lock {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    background: var(--managed);
    color: var(--managed-text);
    padding: 2px var(--space-3);
    border-radius: var(--radius-chip);
    font-size: 12px;
    font-weight: 600;
  }
</style>
