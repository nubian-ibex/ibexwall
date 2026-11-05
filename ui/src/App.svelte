<script lang="ts">
  import { onMount } from 'svelte';
  import { app } from './lib/app.svelte';
  import { i18n } from './lib/i18n.svelte';
  import { applyTheme, savedTheme } from './lib/theme';
  import AppShell from './components/AppShell.svelte';
  import PromptDialog from './components/PromptDialog.svelte';
  import Assistant from './screens/Assistant.svelte';
  import Apps from './screens/Apps.svelte';
  import Dns from './screens/Dns.svelte';
  import Hardening from './screens/Hardening.svelte';
  import Firewall from './screens/Firewall.svelte';
  import History from './screens/History.svelte';
  import Overview from './screens/Overview.svelte';
  import Plugins from './screens/Plugins.svelte';
  import Posture from './screens/Posture.svelte';
  import Settings from './screens/Settings.svelte';

  onMount(() => {
    document.documentElement.lang = i18n.locale;
    applyTheme(savedTheme());
    app.refresh();
    // Held connections are time-limited, so ask often.
    void app.refreshPrompts();
    const timer = setInterval(() => void app.refreshPrompts(), 2000);
    return () => clearInterval(timer);
  });
</script>

<AppShell>
  {#if app.route === 'overview'}
    <Overview />
  {:else if app.route === 'apps'}
    <Apps />
  {:else if app.route === 'firewall'}
    <Firewall />
  {:else if app.route === 'dns'}
    <Dns />
  {:else if app.route === 'posture'}
    <Posture />
  {:else if app.route === 'hardening'}
    <Hardening />
  {:else if app.route === 'plugins'}
    <Plugins />
  {:else if app.route === 'history'}
    <History />
  {:else if app.route === 'assistant'}
    <Assistant />
  {:else if app.route === 'settings'}
    <Settings />
  {/if}
</AppShell>
<PromptDialog />
