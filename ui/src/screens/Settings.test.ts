import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { i18n } from '../lib/i18n.svelte';
import Settings from './Settings.svelte';

describe('Settings', () => {
  beforeEach(() => {
    i18n.set('en');
    document.documentElement.removeAttribute('data-theme');
  });

  it('switches the language and the theme', async () => {
    render(Settings);
    await fireEvent.change(screen.getByLabelText('Theme'), { target: { value: 'dark' } });
    expect(document.documentElement.dataset['theme']).toBe('dark');
    await fireEvent.change(screen.getByLabelText('Language'), { target: { value: 'pt-BR' } });
    expect(i18n.locale).toBe('pt-BR');
  });
});
