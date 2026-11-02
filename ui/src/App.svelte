<script lang="ts">
  import { onMount } from 'svelte';
  import { app } from './lib/app.svelte';
  import { i18n } from './lib/i18n.svelte';
  import AppShell from './components/AppShell.svelte';
  import Overview from './screens/Overview.svelte';

  onMount(() => {
    document.documentElement.lang = i18n.locale;
    app.refresh();
  });
</script>

<AppShell>
  {#if app.route === 'overview'}
    <Overview />
  {:else}
    <h1>{app.route}</h1>
  {/if}
</AppShell>
