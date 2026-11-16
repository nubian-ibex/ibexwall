import { render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../lib/app.svelte';
import { FixtureTransport } from '../lib/fixtures';
import { i18n } from '../lib/i18n.svelte';
import { TransportError } from '../lib/transport';

const invoke = vi.fn(async () => undefined);
// Only the window's own check says "inside Tauri"; the app singleton, built
// at import time, keeps using the fixture core.
const tauri = vi.hoisted(() => ({ inside: false }));
vi.mock('../lib/tauri-transport', async (original) => ({
  ...(await original<object>()),
  insideTauri: () => tauri.inside,
}));
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => invoke(...(args as [])),
}));

import PromptWindow from './PromptWindow.svelte';

describe('PromptWindow', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    i18n.set('en');
    app.prompts = [];
    invoke.mockClear();
    tauri.inside = true;
  });
  afterEach(() => vi.useRealTimers());

  it('stays open and says so when the core cannot be asked', async () => {
    const transport = new FixtureTransport('attention', 0, false);
    transport.listPrompts = () => Promise.reject(new TransportError('unreachable', {}));
    app.useTransport(transport);
    render(PromptWindow);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(invoke).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/cannot reach/i);
  });

  it('closes once an answered empty list is seen repeatedly', async () => {
    app.useTransport(new FixtureTransport('attention', 0, false));
    render(PromptWindow);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(invoke).toHaveBeenCalledWith('finish_prompt');
  });
});
