<script lang="ts">
  import { app } from '../lib/app.svelte';
  import Button from '../components/Button.svelte';
  import { i18n, languageName, LOCALES, t } from '../lib/i18n.svelte';
  import { applyTheme, savedTheme, THEMES, type Theme } from '../lib/theme';

  let theme = $state<Theme>(savedTheme());

  function onTheme(event: Event) {
    theme = (event.currentTarget as HTMLSelectElement).value as Theme;
    applyTheme(theme);
  }

  function onLocale(event: Event) {
    const value = (event.currentTarget as HTMLSelectElement).value;
    i18n.set(value === '' ? null : value);
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
    <select value={i18n.chosen ? i18n.locale : ''} onchange={onLocale}>
      <option value="">{t('language-system', { language: languageName(i18n.locale) })}</option>
      {#each LOCALES as locale (locale)}
        <option value={locale}>{languageName(locale)}</option>
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

<section class="card" aria-labelledby="welcome-again-title">
  <h2 id="welcome-again-title">{t('settings-welcome-title')}</h2>
  <p class="muted">{t('settings-welcome-body')}</p>
  <div>
    <Button onclick={() => (app.route = 'welcome')}>{t('settings-welcome-open')}</Button>
  </div>
</section>

<section class="card" aria-labelledby="managed-title">
  <h2 id="managed-title">{t('settings-managed-title')}</h2>
  {#if app.managed}
    <p>{t('settings-managed-yes')}</p>
    <div>
      <Button onclick={() => (app.route = 'organisation')}>{t('settings-managed-open')}</Button>
    </div>
  {:else}
    <p class="muted">{t('settings-managed-no')}</p>
  {/if}
</section>

<style>
  .card + .card {
    margin-top: var(--space-6);
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  p {
    margin: 0;
  }
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
