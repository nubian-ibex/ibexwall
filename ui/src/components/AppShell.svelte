<script lang="ts">
  import type { Snippet } from 'svelte';
  import { app, type Route } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import Icon from './Icon.svelte';
  import ChangeStatus from './ChangeStatus.svelte';
  import ChangeBar from './ChangeBar.svelte';
  import ChangeLayer from './ChangeLayer.svelte';
  import { changes } from '../lib/changes.svelte';
  import logo from '../assets/logo.png';

  let { children }: { children: Snippet } = $props();

  function pluginState(id: string | undefined): 'on' | 'off' | null {
    if (!id || app.plugins.status !== 'ready') return null;
    const plugin = app.plugins.data.find((p) => p.id === id);
    return plugin ? (plugin.enabled ? 'on' : 'off') : null;
  }

  /** Screens that belong to one plugin carry a dot with its state, so the
   * person sees what is on without visiting each screen. */
  const items: { route: Route; icon: string; key: string; plugin?: string }[] = [
    { route: 'overview', icon: 'layout-grid', key: 'nav-overview' },
    { route: 'apps', icon: 'monitor', key: 'nav-apps', plugin: 'apps.flatpak-network' },
    { route: 'firewall', icon: 'brick-wall', key: 'nav-firewall', plugin: 'net.firewall' },
    { route: 'dns', icon: 'globe', key: 'nav-dns', plugin: 'net.dns' },
    { route: 'posture', icon: 'shield-check', key: 'nav-posture' },
    { route: 'hardening', icon: 'lock-keyhole', key: 'nav-hardening', plugin: 'system.hardening' },
    { route: 'compliance', icon: 'badge-check', key: 'nav-compliance' },
    { route: 'organisation', icon: 'building-2', key: 'nav-organisation' },
    { route: 'plugins', icon: 'clipboard-list', key: 'nav-plugins' },
    { route: 'history', icon: 'clock', key: 'nav-history' },
    { route: 'assistant', icon: 'bot', key: 'nav-assistant' },
    { route: 'settings', icon: 'settings', key: 'nav-settings' },
  ];
</script>

<a class="skip" href="#content">{t('skip-to-content')}</a>
<div class="shell">
  <aside>
    <div class="brand">
      <img class="logo" src={logo} alt="" width="44" height="44" />
      <div>
        <strong>{t('app-name')}</strong>
        <div class="tagline">{t('app-tagline')}</div>
      </div>
    </div>
    <nav aria-label={t('nav-label')}>
      <ul>
        {#each items.filter((item) => item.route !== 'organisation' || app.managed) as item (item.route)}
          <li>
            <button
              type="button"
              class:active={app.route === item.route}
              aria-current={app.route === item.route ? 'page' : undefined}
              onclick={() => (app.route = item.route)}
            >
              <Icon name={item.icon} size={20} />
              {t(item.key)}
              {#if pluginState(item.plugin) !== null}
                {@const state = pluginState(item.plugin)}
                <span
                  class={`state ${state}`}
                  title={t(state === 'on' ? 'plugins-enabled' : 'plugins-disabled')}
                  aria-hidden="true"
                ></span>
              {/if}
              {#if changes.countFor(item.route) > 0}
                <span
                  class="badge"
                  title={t('changebar-title', { count: changes.countFor(item.route) })}
                >
                  {changes.countFor(item.route)}
                </span>
              {/if}
            </button>
          </li>
        {/each}
      </ul>
    </nav>
    <footer class={app.serviceStatus}>
      <div class="status" role="status">
        <span class="dot" aria-hidden="true"></span>{t(`sidebar-status-${app.serviceStatus}`)}
      </div>
      {#if app.info.status === 'ready'}
        <div class="version">
          <span>{t('sidebar-version')}</span>
          <code>{app.info.data.version}</code>
        </div>
      {/if}
    </footer>
  </aside>
  <main id="content" tabindex="-1">
    <div class="content">
      <ChangeStatus />
      {@render children()}
      <ChangeBar />
    </div>
  </main>
  <ChangeLayer />
</div>

<style>
  .skip {
    position: absolute;
    left: -999px;
  }
  .skip:focus {
    left: var(--space-3);
    top: var(--space-3);
    z-index: 10;
    background: var(--surface);
    padding: var(--space-2) var(--space-4);
  }
  /* The window does not scroll: the sidebar stays, with its status at the
     bottom, and only the screen's content scrolls. */
  .shell {
    display: grid;
    grid-template-columns: 280px 1fr;
    height: 100vh;
    height: 100dvh;
    overflow: hidden;
  }
  aside {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
    min-height: 0;
    padding: var(--space-5);
    background: var(--surface);
    border-right: 1px solid var(--border);
  }
  .brand {
    display: flex;
    gap: var(--space-3);
    align-items: center;
  }
  .logo {
    width: 44px;
    height: 44px;
    object-fit: contain;
  }
  .tagline {
    color: var(--muted);
    font-size: 13px;
  }
  nav {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }
  nav ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-1);
  }
  nav button {
    width: 100%;
    min-height: var(--target);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 0 var(--space-4);
    border: 0;
    border-radius: var(--radius-control);
    background: transparent;
    color: var(--text-2);
    font-weight: 500;
    cursor: pointer;
    text-align: left;
  }
  nav button:hover {
    background: var(--surface-2);
  }
  nav .state {
    width: 8px;
    height: 8px;
    margin-left: auto;
    border-radius: 50%;
  }
  nav .state.on {
    background: var(--primary-strong);
  }
  nav .state.off {
    background: var(--muted);
  }
  nav .badge {
    margin-left: auto;
    min-width: 22px;
    height: 22px;
    padding: 0 var(--space-2);
    display: grid;
    place-items: center;
    border-radius: 999px;
    background: var(--primary);
    color: var(--on-primary);
    font-size: 12px;
    font-weight: 700;
  }
  nav button.active {
    background: var(--primary-soft);
    color: var(--primary-strong);
    font-weight: 600;
  }
  footer {
    flex: none;
    display: grid;
    gap: var(--space-2);
    padding-top: var(--space-3);
    border-top: 1px solid var(--divider);
    color: var(--primary-strong);
    font-weight: 600;
    font-size: 14px;
  }
  .status {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .version {
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--muted);
    font-weight: 400;
    font-size: 13px;
  }
  .version code {
    font-family: var(--font-mono);
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0 var(--space-2);
    color: var(--text-2);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
  }
  footer.checking,
  footer.running {
    color: var(--muted);
  }
  footer.degraded {
    color: var(--warning-text);
  }
  footer.offline,
  footer.no-access {
    color: var(--danger);
  }
  main {
    min-height: 0;
    overflow-y: auto;
    outline: none;
  }
  .content {
    padding: var(--space-8) var(--space-10);
    /* One width for every screen. */
    max-width: 1100px;
  }
  @media (max-width: 800px) {
    .shell {
      grid-template-columns: 1fr;
      height: auto;
      overflow: visible;
    }
    nav,
    main {
      overflow: visible;
    }
    aside {
      border-right: 0;
      border-bottom: 1px solid var(--border);
    }
    .content {
      padding: var(--space-5);
    }
  }
</style>
