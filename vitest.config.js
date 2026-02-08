import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    testTimeout: 30000, // 30 seconds per test
    hookTimeout: 30000, // 30 seconds for setup/teardown
    teardownTimeout: 10000,
    globals: true,
  },
})
