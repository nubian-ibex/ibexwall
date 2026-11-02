import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  // Locale files of the check plugins live outside ui/.
  server: { fs: { allow: ['..'] } },
  // Fonts and assets are bundled locally: the app never loads remote content.
  build: { target: 'es2022', assetsInlineLimit: 0 },
  resolve: process.env.VITEST ? { conditions: ['browser'] } : undefined,
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    setupFiles: ['src/test-setup.ts'],
  },
});
