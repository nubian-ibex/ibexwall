<script lang="ts">
  import { t } from '../lib/i18n.svelte';
  import type { CheckResult, Finding } from '../gen/contracts';

  let { severity }: { severity: CheckResult['severity'] | Finding['severity'] } = $props();
</script>

<span class="severity {severity}">{t(`severity-${severity}`)}</span>

<style>
  .severity {
    font-size: 12px;
    font-weight: 600;
    padding: 1px var(--space-2);
    border-radius: var(--radius-chip);
  }
  .info {
    background: var(--info-soft);
    color: var(--info);
  }
  .low {
    background: var(--info-soft);
    color: var(--info);
  }
  .medium {
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .high {
    background: var(--warning-soft);
    color: var(--warning-text);
  }
  .critical {
    background: var(--danger-soft);
    color: var(--danger);
  }
</style>
