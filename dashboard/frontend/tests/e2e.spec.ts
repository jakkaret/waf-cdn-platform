import { test, expect, Page } from '@playwright/test'

// ── Test Credentials ──────────────────────────────────────────────────────
const TEST_EMAIL    = `e2e_test_${Date.now()}@test.local`
const TEST_USERNAME = `e2e_user_${Date.now()}`
const TEST_PASSWORD = 'E2eTestP@ss123!'
const API_BASE      = 'http://localhost:8000'

// ── Helpers ───────────────────────────────────────────────────────────────
async function register(page: Page, email: string, username: string, password: string) {
  await page.goto('/register')
  await page.getByPlaceholder(/email/i).fill(email)
  await page.getByPlaceholder(/username/i).fill(username)
  await page.getByPlaceholder(/password/i).fill(password)
  await page.getByRole('button', { name: /register|sign up/i }).click()
}

async function login(page: Page, email: string, password: string) {
  await page.goto('/login')
  await page.getByPlaceholder(/email/i).fill(email)
  await page.getByPlaceholder(/password/i).fill(password)
  await page.getByRole('button', { name: /login|sign in/i }).click()
}

// ── Test Suite ────────────────────────────────────────────────────────────

test.describe('Auth Flow', () => {
  test('Register → auto-redirect to dashboard', async ({ page }) => {
    await register(page, TEST_EMAIL, TEST_USERNAME, TEST_PASSWORD)

    // Should redirect away from /register after successful registration
    await expect(page).not.toHaveURL(/\/register/, { timeout: 8_000 })

    // Dashboard should show the app layout (not login page)
    await expect(page.locator('body')).not.toContainText('Sign In', { timeout: 5_000 })
  })

  test('Login with valid credentials', async ({ page }) => {
    // Register first (fresh credentials per run)
    await register(page, TEST_EMAIL + '.login', TEST_USERNAME + '_L', TEST_PASSWORD)
    await page.goto('/login')

    await login(page, TEST_EMAIL + '.login', TEST_PASSWORD)
    await expect(page).not.toHaveURL(/\/login/, { timeout: 8_000 })
  })

  test('Login with wrong password shows error', async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder(/email/i).fill('nonexistent@test.local')
    await page.getByPlaceholder(/password/i).fill('WrongPass!')
    await page.getByRole('button', { name: /login|sign in/i }).click()

    // Should stay on login or show error toast
    await expect(
      page.locator('body')
    ).toContainText(/invalid|incorrect|error|wrong/i, { timeout: 5_000 })
  })
})

test.describe('Origins Management', () => {
  // Log in before each test in this group
  test.beforeEach(async ({ page }) => {
    await register(page, TEST_EMAIL + '.orig', TEST_USERNAME + '_O', TEST_PASSWORD)
    // If register redirects to dashboard, we're already logged in
    await page.waitForURL(url => !url.pathname.includes('/register'), { timeout: 8_000 })
  })

  test('Origins page loads and shows quota bar', async ({ page }) => {
    await page.goto('/origins')
    await expect(page.locator('body')).toContainText(/origin quota/i, { timeout: 8_000 })
    // Quota text "0 / 5 used" or similar
    await expect(page.locator('body')).toContainText(/\d\s*\/\s*\d/)
  })

  test('Add Origin → appears in list', async ({ page }) => {
    await page.goto('/origins')

    // Click Add Origin
    await page.getByRole('button', { name: /add origin/i }).click()

    // Fill form (modal)
    await page.getByPlaceholder(/label|name/i).first().fill('E2E Test Server')
    await page.getByPlaceholder(/ip|address/i).fill('192.168.1.100')
    await page.getByPlaceholder(/port/i).fill('8080')

    // Submit
    await page.getByRole('button', { name: /add|create|save/i }).last().click()

    // Origin card should appear
    await expect(page.locator('body')).toContainText('E2E Test Server', { timeout: 8_000 })
  })
})

test.describe('WAF Rules Page', () => {
  test.beforeEach(async ({ page }) => {
    await register(page, TEST_EMAIL + '.rules', TEST_USERNAME + '_R', TEST_PASSWORD)
    await page.waitForURL(url => !url.pathname.includes('/register'), { timeout: 8_000 })
  })

  test('Rules page loads', async ({ page }) => {
    await page.goto('/rules')
    await expect(page.locator('body')).toContainText(/custom rules|waf/i, { timeout: 8_000 })
  })

  test('Sync to Edge Nodes button visible for admin', async ({ page }) => {
    await page.goto('/rules')
    // Admin user (first registered) should see the Sync button
    await expect(
      page.getByRole('button', { name: /sync to edge/i })
    ).toBeVisible({ timeout: 8_000 })
  })
})

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await register(page, TEST_EMAIL + '.dash', TEST_USERNAME + '_D', TEST_PASSWORD)
    await page.waitForURL(url => !url.pathname.includes('/register'), { timeout: 8_000 })
  })

  test('Dashboard loads with key sections', async ({ page }) => {
    await page.goto('/')
    // Should contain at least one recognizable dashboard element
    await expect(page.locator('body')).toContainText(
      /dashboard|security|threat|CDN|nodes/i,
      { timeout: 10_000 }
    )
  })

  test('Navigate to CDN page', async ({ page }) => {
    await page.goto('/cdn')
    await expect(page.locator('body')).toContainText(/CDN|edge|node|region/i, { timeout: 8_000 })
  })
})
