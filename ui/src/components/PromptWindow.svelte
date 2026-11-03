<script lang="ts">
  import { onMount } from 'svelte';
  import { app } from '../lib/app.svelte';
  import { i18n } from '../lib/i18n.svelte';
  import { applyTheme, savedTheme } from '../lib/theme';
  import { insideTauri } from '../lib/tauri-transport';
  import PromptDialog from './PromptDialog.svelte';

  // The window `ibexwall --prompt` opens: only the question, and it closes
  // itself once nothing is waiting (answered, or the timeout passed).
  let seen = false;
  let idle = 0;

  async function finish() {
    if (!insideTauri()) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('finish_prompt');
  }

  onMount(() => {
    document.documentElement.lang = i18n.locale;
    applyTheme(savedTheme());
    const tick = async () => {
      await app.refreshPrompts();
      if (app.prompts.length > 0) {
        seen = true;
        idle = 0;
      } else if (++idle >= (seen ? 1 : 4)) {
        await finish();
      }
    };
    void tick();
    const timer = setInterval(() => void tick(), 1000);
    return () => clearInterval(timer);
  });
</script>

<PromptDialog standalone />
