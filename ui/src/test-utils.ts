import { render } from '@testing-library/svelte';
import ChangeBar from './components/ChangeBar.svelte';
import ChangeLayer from './components/ChangeLayer.svelte';

/** Renders a screen together with the change bar and review panel the app shell provides. */
export function renderScreen(
  screen: Parameters<typeof render>[0],
  props?: Record<string, unknown>,
) {
  const result = render(screen, props as never);
  render(ChangeBar);
  render(ChangeLayer);
  return result;
}
