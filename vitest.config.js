import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    testTimeout: 60000, // 60 seconds per test
    hookTimeout: 60000, // 60 seconds for setup/teardown
    teardownTimeout: 10000,
    globals: true,
    fileParallelism: false, // Run test files sequentially to avoid resource contention
    exclude: ['**/node_modules/**', '**/dist/**', 'code-review-agent/**'], // code-review-agent has its own vitest config and deps
  },
})
