import { defineConfig } from 'vitest/config'

// Unit tests live beside the code as src/**/*.test.ts. The Playwright e2e suite
// under tests/ is driven by @playwright/test, not vitest, so it is excluded here
// to keep `npm run test:unit` scoped to the pure unit tests.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    exclude: ['node_modules', 'dist', 'tests/**'],
  },
})
