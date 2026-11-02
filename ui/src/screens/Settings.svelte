<script lang="ts">
  import { i18n, LOCALES, t, type Locale } from '../lib/i18n.svelte';
  import { applyTheme, savedTheme, THEMES, type Theme } from '../lib/theme';

  let theme = $state<Theme>(savedTheme());

  function onTheme(event: Event) {
    theme = (event.currentTarget as HTMLSelectElement).value as Theme;
    applyTheme(theme);
  }

  function onLocale(event: Event) {
    i18n.set((event.currentTarget as HTMLSelectElement).value as Locale);
  }
</script>

<header class="page-head">
  <div>
    <h1>{t('settings-title')}</h1>
    <p class="muted">{t('settings-subtitle')}</p>
  </div>
</header>

<section class="card">
  <label>
    <span>{t('language-label')}</span>
    <select value={i18n.locale} onchange={onLocale}>
      {#each LOCALES as locale (locale)}
        <option value={locale}>{t(`language-${locale}`)}</option>
      {/each}
    </select>
  </label>
  <label>
    <span>{t('theme-label')}</span>
    <select value={theme} onchange={onTheme}>
      {#each THEMES as option (option)}
        <option value={option}>{t(`theme-${option}`)}</option>
      {/each}
    </select>
  </label>
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
  label {
    display: grid;
    gap: var(--space-2);
    font-weight: 600;
  }
  select {
    min-height: var(--target);
    padding: 0 var(--space-3);
    background: var(--surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-control);
  }
</style>
