<script lang="ts">
  import { onMount } from 'svelte';
  import { app } from './lib/app.svelte';
  import { i18n } from './lib/i18n.svelte';
  import { applyTheme, savedTheme } from './lib/theme';
  import AppShell from './components/AppShell.svelte';
  import History from './screens/History.svelte';
  import Overview from './screens/Overview.svelte';
  import Plugins from './screens/Plugins.svelte';
  import Posture from './screens/Posture.svelte';
  import Settings from './screens/Settings.svelte';

  onMount(() => {
    document.documentElement.lang = i18n.locale;
    applyTheme(savedTheme());
    app.refresh();
  });
</script>

<AppShell>
  {#if app.route === 'overview'}
    <Overview />
  {:else if app.route === 'posture'}
    <Posture />
  {:else if app.route === 'plugins'}
    <Plugins />
  {:else if app.route === 'history'}
    <History />
  {:else if app.route === 'settings'}
    <Settings />
  {/if}
</AppShell>
