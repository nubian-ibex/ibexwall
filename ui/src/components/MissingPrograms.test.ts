import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { i18n } from '../lib/i18n.svelte';
import type { Finding } from '../gen/contracts';
import MissingPrograms from './MissingPrograms.svelte';

function note(id: string, plugin: string, args: Record<string, string>): Finding {
  return {
    id,
    plugin,
    severity: 'info',
    title_key: 'missing-title',
    summary_key: 'missing-body',
    args,
    references: [],
    remediation: null,
    status: 'open',
    detected_at: '2026-11-09T00:00:00Z',
  } as Finding;
}

describe('MissingPrograms', () => {
  beforeEach(() => i18n.set('en'));

  it('lists only the notes that carry an install command, and copies it', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    app.findings = {
      status: 'ready',
      data: [
        note('detect.exposure', 'net.exposure', { install: 'sudo apt install nmap', case: 'none' }),
        note('detect.dns', 'net.dns', { case: 'resolved' }),
      ],
    };
    render(MissingPrograms);
    expect(screen.getByText('sudo apt install nmap')).toBeVisible();
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
    await fireEvent.click(screen.getByRole('button', { name: 'Copy the command' }));
    expect(writeText).toHaveBeenCalledWith('sudo apt install nmap');
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeVisible();
  });

  it('shows nothing when nothing is missing', () => {
    app.findings = { status: 'ready', data: [] };
    render(MissingPrograms);
    expect(screen.queryByRole('heading')).toBeNull();
  });
});
