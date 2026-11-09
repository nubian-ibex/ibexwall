import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it } from 'vitest';
import { app } from '../lib/app.svelte';
import { i18n } from '../lib/i18n.svelte';
import { changeErrorKey, TransportError } from '../lib/transport';
import ChangeStatus from './ChangeStatus.svelte';

describe('ChangeStatus', () => {
  beforeEach(() => {
    i18n.set('en');
    app.changing = 0;
    app.notice = null;
  });

  it('says it waits for authorization while a change is pending', async () => {
    render(ChangeStatus);
    let release: () => void = () => {};
    const pending = app.change(() => new Promise<void>((resolve) => (release = resolve)));
    expect(await screen.findByRole('status')).toHaveTextContent(/waiting for authorization/i);
    release();
    await pending;
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('explains a missing password dialog, and can be dismissed', async () => {
    render(ChangeStatus);
    await app.change(() =>
      Promise.reject(
        new TransportError('com.ibexwall.Core.AuthenticationRequired', {
          action: 'com.ibexwall.apply',
          interactive_possible: false,
        }),
      ),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(/no password dialog/i);
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('tells a refusal from a missing password', () => {
    const refused = new TransportError('com.ibexwall.Core.PermissionDenied', {
      action: 'com.ibexwall.apply',
    });
    const needed = new TransportError('com.ibexwall.Core.AuthenticationRequired', {
      action: 'com.ibexwall.apply',
      interactive_possible: true,
    });
    expect(changeErrorKey(refused)).toBe('auth-refused');
    expect(changeErrorKey(needed)).toBe('auth-required');
    expect(changeErrorKey(new Error('boom'))).toBe('change-failed-other');
  });

  it('speaks Portuguese', async () => {
    i18n.set('pt-BR');
    render(ChangeStatus);
    await app.change(() =>
      Promise.reject(new TransportError('com.ibexwall.Core.PermissionDenied', {})),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(/não foi autorizada/);
  });
});
