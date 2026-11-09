<script lang="ts">
  // The first run: what IbexWall does, a first check, the protections to
  // turn on (one password), what is missing, and the organisation entry.
  // Shown once after install; Settings can open it again.
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { RECOMMENDED, finishWelcome } from '../lib/welcome';
  import type { PluginInfo } from '../gen/contracts';
  import Button from '../components/Button.svelte';
  import MissingPrograms from '../components/MissingPrograms.svelte';

  const STEPS = ['intro', 'check', 'protect', 'missing', 'organisation'] as const;
  let step = $state(0);
  let checked = $state(false);
  let chosen = $state<string[]>([...RECOMMENDED]);
  let turnedOn = $state<string[]>([]);
  let busy = $state(false);

  const name = (plugin: PluginInfo) => plugin.names?.[i18n.locale] ?? plugin.name;
  const offers = $derived(
    app.plugins.status === 'ready'
      ? app.plugins.data.filter(
          (p) => RECOMMENDED.includes(p.id) && !p.enabled && p.compatible && !p.locked,
        )
      : [],
  );

  async function check() {
    busy = true;
    try {
      await app.checkNow();
      checked = true;
    } finally {
      busy = false;
    }
  }

  async function turnOn() {
    busy = true;
    try {
      // One password: polkit keeps the answer for the following calls.
      for (const id of chosen.filter((id) => offers.some((p) => p.id === id))) {
        const done = await app.change(() => app.transport.setPluginEnabled(id, true));
        if (done === undefined && app.notice) break;
        turnedOn = [...turnedOn, id];
      }
      await app.refresh();
    } finally {
      busy = false;
    }
  }

  function toggle(id: string, on: boolean) {
    chosen = on ? [...chosen, id] : chosen.filter((x) => x !== id);
  }

  function finish() {
    finishWelcome();
    app.route = 'overview';
  }
</script>

<header class="page-head">
  <div>
    <p class="muted">{t('welcome-step', { step: step + 1, total: STEPS.length })}</p>
    <h1>{t(`welcome-${STEPS[step]}-title`)}</h1>
  </div>
</header>

<section class="card">
  {#if STEPS[step] === 'intro'}
    <p>{t('welcome-intro-body')}</p>
    <p>{t('welcome-intro-password')}</p>
    <p class="muted">{t('welcome-intro-admins')}</p>
    <p class="muted">{t('welcome-intro-local')}</p>
  {:else if STEPS[step] === 'check'}
    <p>{t('welcome-check-body')}</p>
    <div>
      <Button variant="primary" {busy} onclick={check}>
        {t(checked ? 'welcome-check-again' : 'welcome-check-run')}
      </Button>
    </div>
    {#if checked && app.posture.status === 'ready'}
      <p role="status">
        {app.posture.data.score == null
          ? t('overview-summary-unknown')
          : t('welcome-check-score', { score: app.posture.data.score })}
      </p>
    {/if}
  {:else if STEPS[step] === 'protect'}
    <p>{t('welcome-protect-body')}</p>
    {#if offers.length === 0 && turnedOn.length === 0}
      <p class="muted">{t('welcome-protect-none')}</p>
    {:else}
      <ul class="choices">
        {#each offers as plugin (plugin.id)}
          <li>
            <label>
              <input
                type="checkbox"
                checked={chosen.includes(plugin.id)}
                onchange={(e) => toggle(plugin.id, e.currentTarget.checked)}
              />
              <span>{name(plugin)}</span>
            </label>
          </li>
        {/each}
      </ul>
      {#if offers.length > 0}
        <div>
          <Button variant="primary" {busy} disabled={chosen.length === 0} onclick={turnOn}>
            {t('welcome-protect-turn-on')}
          </Button>
        </div>
      {/if}
      {#if turnedOn.length > 0}
        <p role="status">{t('welcome-protect-done', { count: turnedOn.length })}</p>
      {/if}
    {/if}
  {:else if STEPS[step] === 'missing'}
    <p>{t('welcome-missing-body')}</p>
    <MissingPrograms />
  {:else}
    <p>{t(app.managed ? 'settings-managed-yes' : 'welcome-organisation-body')}</p>
  {/if}
</section>

<nav class="steps" aria-label={t('welcome-nav')}>
  {#if step > 0}
    <Button onclick={() => (step -= 1)}>{t('welcome-back')}</Button>
  {/if}
  <span class="spacer"></span>
  {#if step < STEPS.length - 1}
    <Button variant="link" onclick={finish}>{t('welcome-skip')}</Button>
    <Button variant="primary" onclick={() => (step += 1)}>{t('welcome-next')}</Button>
  {:else}
    <Button variant="primary" onclick={finish}>{t('welcome-finish')}</Button>
  {/if}
</nav>

<style>
  .page-head {
    margin-bottom: var(--space-6);
  }
  h1 {
    font-size: 28px;
  }
  .card {
    display: grid;
    gap: var(--space-4);
    max-width: 720px;
    padding: var(--space-6);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  p {
    margin: 0;
  }
  .choices {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-2);
  }
  label {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: var(--target);
  }
  .steps {
    display: flex;
    gap: var(--space-3);
    align-items: center;
    max-width: 720px;
    margin-top: var(--space-6);
  }
  .spacer {
    flex: 1;
  }
</style>
