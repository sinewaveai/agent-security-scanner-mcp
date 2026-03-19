import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30_000,
    include: ['tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
  },
});
