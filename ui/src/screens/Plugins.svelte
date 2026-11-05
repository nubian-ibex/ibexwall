<script lang="ts">
  import { app } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import type { PluginInfo } from '../gen/contracts';
  import Button from '../components/Button.svelte';
  import ChangeFlow from '../components/ChangeFlow.svelte';
  import Detected from '../components/Detected.svelte';
  import FindingRow from '../components/FindingRow.svelte';
  import LockBadge from '../components/LockBadge.svelte';
  import StateMessage from '../components/StateMessage.svelte';
  import Switch from '../components/Switch.svelte';

  let selected = $state<PluginInfo | null>(null);
  let manifest = $state<Record<string, unknown> | null>(null);
  let busy = $state(false);

  const plugins = $derived(app.plugins.status === 'ready' ? app.plugins.data : []);
  const findings = $derived.by(() => {
    const current = selected;
    if (app.findings.status !== 'ready' || !current) return [];
    return app.findings.data.filter((f) => f.plugin === current.id && !f.id.startsWith('detect.'));
  });

  async function toggle(plugin: PluginInfo, value: boolean) {
    busy = true;
    try {
      await app.transport.setPluginEnabled(plugin.id, value);
      await app.refresh();
    } finally {
      busy = false;
    }
  }

  async function openDetail(plugin: PluginInfo) {
    selected = plugin;
    manifest = null;
    const next = await app.transport.getManifest(plugin.id);
    if (selected?.id === plugin.id) manifest = next;
  }

  /** Permissions in plain words, with the technical line below. */
  const permissions = $derived.by(() => {
    if (!manifest) return [];
    const privileges = (manifest.privileges ?? {}) as Record<string, unknown>;
    const list: { text: string; detail: string }[] = [];
    const paths = (privileges.write_paths ?? []) as string[];
    if (paths.length > 0) {
      list.push({
        text: t('plugins-permissions-write', { paths: paths.join(', ') }),
        detail: paths.join('\n'),
      });
    }
    const units = (privileges.units ?? []) as string[];
    if (units.length > 0) {
      list.push({
        text: t('plugins-permissions-units', { units: units.join(', ') }),
        detail: units.join('\n'),
      });
    }
    const keys = (privileges.sysctl_keys ?? []) as string[];
    if (keys.length > 0) {
      list.push({
        text: t('plugins-permissions-sysctl', { keys: keys.join(', ') }),
        detail: keys.join('\n'),
      });
    }
    const exec = (privileges.exec ?? []) as { path: string }[];
    if (exec.length > 0) {
      list.push({
        text: t('plugins-permissions-exec', { commands: exec.map((e) => e.path).join(', ') }),
        detail: exec.map((e) => e.path).join('\n'),
      });
    }
    if (privileges.nft_prefix)
      list.push({ text: t('plugins-permissions-nft'), detail: String(privileges.nft_prefix) });
    if (list.length === 0) list.push({ text: t('plugins-permissions-none'), detail: '' });
    return list;
  });
</script>

<header class="page-head">
  <div>
    <h1>{t('plugins-title')}</h1>
    <p class="muted">{t('plugins-subtitle')}</p>
  </div>
</header>

{#if app.plugins.status === 'loading'}
  <StateMessage kind="loading" />
{:else if app.plugins.status === 'error'}
  <StateMessage kind="error" onretry={() => app.refresh()} />
{:else}
  <ul class="list">
    {#each plugins as plugin (plugin.id)}
      <li>
        <article class="row" class:open={selected?.id === plugin.id}>
          <div class="id">
            <h3>{plugin.name}</h3>
            <span class="mono">{plugin.id} · {plugin.version}</span>
          </div>
          <div class="meta">
            <span class="mono">{t(`plugins-kind-${(plugin.kinds ?? ['check'])[0]}`)}</span>
            <span class="mono">{t(`plugins-origin-${plugin.origin}`)}</span>
            {#if plugin.locked}
              <LockBadge />
            {/if}
          </div>
          <Switch
            checked={plugin.enabled}
            label={t(plugin.enabled ? 'plugins-enabled' : 'plugins-disabled')}
            disabled={busy || plugin.locked}
            onchange={(value) => toggle(plugin, value)}
          />
          <Button onclick={() => openDetail(plugin)}>{t('plugins-detail')}</Button>
        </article>

        {#if selected?.id === plugin.id}
          <section class="detail" aria-label={plugin.name}>
            <h2>{t('plugins-permissions')}</h2>
            <ul class="permissions">
              {#each permissions as permission (permission.text)}
                <li>
                  <span>{permission.text}</span>
                  {#if permission.detail}
                    <pre class="mono">{permission.detail}</pre>
                  {/if}
                </li>
              {/each}
            </ul>

            <Detected plugin={selected.id} />

            {#if findings.length > 0}
              <h2>{t('plugins-findings')}</h2>
              <div class="findings">
                {#each findings as finding (finding.id)}
                  <FindingRow {finding} />
                {/each}
              </div>
            {:else}
              <p class="muted">{t('plugins-no-findings')}</p>
            {/if}

            {#if (plugin.kinds ?? []).includes('control')}
              <ChangeFlow plugin={plugin.id} />
            {/if}
          </section>
        {/if}
      </li>
    {/each}
  </ul>
{/if}

<style>
  .page-head {
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  .muted {
    color: var(--muted);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .row {
    display: grid;
    grid-template-columns: 1fr auto auto auto;
    gap: var(--space-4);
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4) var(--space-5);
  }
  .row.open {
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  h3 {
    font-size: 16px;
  }
  .meta {
    display: flex;
    gap: var(--space-4);
    align-items: center;
  }
  .detail {
    background: var(--surface);
    border: 1px solid var(--border);
    border-top: none;
    border-radius: 0 0 var(--radius-card) var(--radius-card);
    padding: var(--space-5);
    display: grid;
    gap: var(--space-4);
  }
  .detail h2 {
    font-size: 16px;
  }
  .permissions {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .permissions li {
    display: grid;
    gap: var(--space-1);
  }
  pre {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    background: var(--surface-2);
    border-radius: var(--radius-control);
    white-space: pre-wrap;
  }
  .findings {
    display: grid;
    gap: var(--space-3);
  }
</style>
