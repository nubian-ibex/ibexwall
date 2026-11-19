import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/svelte';
import { afterEach } from 'vitest';
import { changes } from './lib/changes.svelte';

// Without globals: true, testing-library does not clean up by itself and
// queries would match elements from previous tests.
afterEach(() => {
  cleanup();
  changes.close();
  changes.discard();
});
