<!-- System snapshots before risky changes (ADR-0050). -->
<script lang="ts">
  import type { SystemSnapshotStatus } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import { changeErrorKey } from '../lib/transport';
  import Switch from './Switch.svelte';

  let status = $state<SystemSnapshotStatus | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function load() {
    try {
      status = await app.transport.getSystemSnapshots();
    } catch (reason) {
      error = t(changeErrorKey(reason));
    }
  }
  load();

  async function toggle(enabled: boolean) {
    if (busy) return;
    busy = true;
    error = null;
    try {
      await app.waiting(() => app.transport.setSystemSnapshots(enabled));
    } catch (reason) {
      error = t(changeErrorKey(reason));
    }
    // Whatever happened, show what the service now says.
    await load();
    busy = false;
  }
</script>

<section class="card" aria-labelledby="snapshots-title">
  <div class="head">
    <h2 id="snapshots-title">{t('settings-snapshots-title')}</h2>
    {#if status}
      <Switch
        checked={status.enabled}
        label={t('settings-snapshots-title')}
        disabled={busy || (!status.available && !status.enabled)}
        onchange={toggle}
      />
    {/if}
  </div>
  <p class="muted">{t('settings-snapshots-body')}</p>
  {#if status && !status.available}
    <p>{t('settings-snapshots-unavailable', { reason: status.reason ?? '' })}</p>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>

<style>
  .card {
    display: grid;
    gap: var(--space-4);
    max-width: 480px;
    padding: var(--space-6);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  .head {
    display: flex;
    justify-content: space-between;
    gap: var(--space-4);
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .error {
    color: var(--danger-strong);
  }
</style>
