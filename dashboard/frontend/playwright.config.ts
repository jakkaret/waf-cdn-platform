import { defineConfig, devices } from '@playwright/test'

// E2E_BASE_URL set  -> run against that live system (full journeys in
//                      tests/e2e.spec.ts need a real backend), no local server.
// unset, CI         -> serve the built dist with `vite preview` (smoke tests only).
// unset, locally    -> `npm run dev`.
const external = process.env.E2E_BASE_URL
const baseURL = external || 'http://localhost:5173'

// The UI defaults to Thai (src/i18n); the specs select elements by their
// English text, so every test starts with the language switch set to EN.
const englishUi = {
  cookies: [],
  origins: [
    {
      origin: new URL(baseURL).origin,
      localStorage: [{ name: 'waf_lang', value: JSON.stringify({ state: { lang: 'en' }, version: 0 }) }],
    },
  ],
}

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  retries: 1,
  reporter: [['html', { outputFolder: 'playwright-report', open: 'never' }], ['list']],
  use: {
    baseURL,
    storageState: englishUi,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // Start dev server before tests
  webServer: external
    ? undefined
    : {
        command: process.env.CI ? 'npx vite preview --port 5173 --strictPort' : 'npm run dev',
        url: 'http://localhost:5173',
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
})
