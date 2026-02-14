import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    testTimeout: 60000, // 60 seconds per test
    hookTimeout: 60000, // 60 seconds for setup/teardown
    teardownTimeout: 10000,
    globals: true,
    fileParallelism: false, // Run test files sequentially to avoid resource contention
  },
})
