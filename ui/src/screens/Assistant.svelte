<script lang="ts">
  import type { Proposal } from '../gen/contracts';
  import { app } from '../lib/app.svelte';
  import { i18n, t } from '../lib/i18n.svelte';
  import { relativeTime } from '../lib/time';
  import { TransportError } from '../lib/transport';
  import Button from '../components/Button.svelte';
  import Callouts from '../components/Callouts.svelte';
  import DiffViewer from '../components/DiffViewer.svelte';
  import StateMessage from '../components/StateMessage.svelte';

  let proposals = $state<Proposal[] | null>(null);
  let failed = $state(false);
  let busy = $state<string | null>(null);
  let problem = $state<string | null>(null);

  const pending = $derived((proposals ?? []).filter((p) => p.status === 'pending'));
  const decided = $derived((proposals ?? []).filter((p) => p.status !== 'pending'));

  async function load() {
    proposals = null;
    failed = false;
    try {
      proposals = await app.transport.listProposals();
    } catch {
      failed = true;
    }
  }
  load();

  async function decide(id: string, decision: 'approve' | 'reject') {
    busy = id;
    problem = null;
    try {
      await app.transport.decideProposal(id, decision);
    } catch (error) {
      problem =
        error instanceof TransportError && error.code.endsWith('.ProposalStale')
          ? 'assistant-stale'
          : 'assistant-failed';
    } finally {
      busy = null;
    }
    proposals = await app.transport.listProposals().catch(() => proposals);
    if (decision === 'approve') void app.refresh();
  }
</script>

<header class="page-head">
  <h1>{t('assistant-title')}</h1>
  <p class="muted">{t('assistant-subtitle')}</p>
</header>

<section class="promise" aria-labelledby="promise-title">
  <h2 id="promise-title">{t('assistant-promise-title')}</h2>
  <ul>
    <li>{t('assistant-promise-propose')}</li>
    <li>{t('assistant-promise-log')}</li>
    <li>{t('assistant-promise-undo')}</li>
  </ul>
</section>

{#if problem}
  <p class="problem" role="alert">{t(problem)}</p>
{/if}

{#if failed}
  <StateMessage kind="error" onretry={load} />
{:else if proposals === null}
  <StateMessage kind="loading" />
{:else if proposals.length === 0}
  <section class="empty">
    <h2>{t('assistant-empty-title')}</h2>
    <p>{t('assistant-empty-body')}</p>
  </section>
{:else}
  {#if pending.length > 0}
    <h2 class="group">{t('assistant-pending-title', { count: pending.length })}</h2>
    <ul class="list">
      {#each pending as p (p.id)}
        <li>
          <article class="card" aria-labelledby={`h-${p.id}`}>
            <h3 id={`h-${p.id}`} class="mono">{p.plugin}</h3>
            <p class="from">{t('assistant-from', { client: p.client })}</p>

            <h4>{t('assistant-says')}</h4>
            <blockquote class="said">{p.justification}</blockquote>

            <h4>{t('assistant-would-do')}</h4>
            <DiffViewer ops={p.preview} />
            <Callouts keys={p.may_affect_keys} />
            <p class="facts">
              {p.reversible === 'reboot'
                ? t('assistant-reversible-reboot')
                : t('assistant-reversible-immediate')}
              {#if p.requires_confirm}
                · {t('assistant-confirm-needed')}
              {/if}
            </p>

            <div class="actions">
              <Button variant="primary" busy={busy === p.id} onclick={() => decide(p.id, 'approve')}
                >{t('assistant-approve')}</Button
              >
              <Button busy={busy === p.id} onclick={() => decide(p.id, 'reject')}
                >{t('assistant-reject')}</Button
              >
            </div>
          </article>
        </li>
      {/each}
    </ul>
  {/if}

  {#if decided.length > 0}
    <h2 class="group">{t('assistant-decided-title')}</h2>
    <ul class="list">
      {#each decided as p (p.id)}
        <li class="done">
          <span class="mono">{p.plugin}</span>
          <span>{t(`assistant-status-${p.status}`)}</span>
          <span class="muted">{relativeTime(p.decided_at ?? p.created_at, i18n.locale)}</span>
        </li>
      {/each}
    </ul>
  {/if}
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
  .promise,
  .empty,
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-5);
  }
  .promise {
    margin-bottom: var(--space-6);
  }
  .promise ul {
    margin: var(--space-2) 0 0;
    padding-left: var(--space-5);
    color: var(--text-2);
  }
  .group {
    margin: var(--space-6) 0 var(--space-3);
    font-size: 18px;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--space-3);
  }
  .card {
    display: grid;
    gap: var(--space-3);
  }
  h4 {
    margin: var(--space-2) 0 0;
    font-size: 14px;
    color: var(--text-2);
  }
  .from {
    color: var(--text-2);
  }
  .said {
    margin: 0;
    padding: var(--space-3) var(--space-4);
    border-left: 4px solid var(--border);
    background: var(--bg);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .facts {
    color: var(--text-2);
    font-size: 14px;
  }
  .actions {
    display: flex;
    gap: var(--space-3);
  }
  .done {
    display: grid;
    grid-template-columns: 1fr 1fr auto;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-5);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
  }
  .problem {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
  }
  .empty p {
    color: var(--text-2);
  }
</style>
