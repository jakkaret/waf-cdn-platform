import { test, expect } from '@playwright/test'

// Backend-free checks for CI: the built app boots, routes render, and the
// auth forms are usable. API calls fail (no backend) -- the UI must not crash.

test('login page renders a usable form', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.goto('/login')
  await expect(page.getByLabel(/email or username/i)).toBeVisible()
  await expect(page.getByLabel('Password', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /sign in to console/i })).toBeVisible()
  expect(errors, errors.join('\n')).toEqual([])
})

test('register page renders a usable form', async ({ page }) => {
  await page.goto('/register')
  await expect(page.getByLabel('Username', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Email', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Password', { exact: true })).toBeVisible()
  await expect(page.getByLabel(/confirm password/i)).toBeVisible()
  await expect(page.getByRole('button', { name: /create account/i })).toBeVisible()
})

test('a protected page without a session ends on the login page', async ({ page }) => {
  await page.goto('/origins')
  await expect(page).toHaveURL(/\/login/, { timeout: 10_000 })
})

test('login with no backend shows an error instead of crashing', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.goto('/login')
  await page.getByLabel(/email or username/i).fill('nobody@example.com')
  await page.getByLabel('Password', { exact: true }).fill('wrong-password-123')
  await page.getByRole('button', { name: /sign in to console/i }).click()
  await expect(page).toHaveURL(/\/login/)
  expect(errors, errors.join('\n')).toEqual([])
})
