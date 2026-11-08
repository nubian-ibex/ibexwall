<script lang="ts">
  import type { Snippet } from 'svelte';
  import { app, type Route } from '../lib/app.svelte';
  import { t } from '../lib/i18n.svelte';
  import Icon from './Icon.svelte';
  import logo from '../assets/logo.png';

  let { children }: { children: Snippet } = $props();

  const items: { route: Route; icon: string; key: string }[] = [
    { route: 'overview', icon: 'layout-grid', key: 'nav-overview' },
    { route: 'apps', icon: 'monitor', key: 'nav-apps' },
    { route: 'firewall', icon: 'brick-wall', key: 'nav-firewall' },
    { route: 'dns', icon: 'globe', key: 'nav-dns' },
    { route: 'posture', icon: 'shield-check', key: 'nav-posture' },
    { route: 'hardening', icon: 'lock-keyhole', key: 'nav-hardening' },
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
        {#each items as item (item.route)}
          <li>
            <button
              type="button"
              class:active={app.route === item.route}
              aria-current={app.route === item.route ? 'page' : undefined}
              onclick={() => (app.route = item.route)}
            >
              <Icon name={item.icon} size={20} />
              {t(item.key)}
            </button>
          </li>
        {/each}
      </ul>
    </nav>
    <footer><span class="dot" aria-hidden="true"></span>{t('sidebar-status-active')}</footer>
  </aside>
  <main id="content" tabindex="-1">{@render children()}</main>
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
  .shell {
    display: grid;
    grid-template-columns: 280px 1fr;
    min-height: 100%;
  }
  aside {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
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
  nav button.active {
    background: var(--primary-soft);
    color: var(--primary-strong);
    font-weight: 600;
  }
  footer {
    margin-top: auto;
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--primary-strong);
    font-weight: 600;
    font-size: 14px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--primary);
  }
  main {
    padding: var(--space-10);
    max-width: 1200px;
    outline: none;
  }
  @media (max-width: 800px) {
    .shell {
      grid-template-columns: 1fr;
    }
    aside {
      border-right: 0;
      border-bottom: 1px solid var(--border);
    }
    main {
      padding: var(--space-5);
    }
  }
</style>
