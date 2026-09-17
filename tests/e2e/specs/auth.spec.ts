import { expect, test } from '@playwright/test'

// Credential values can appear in Playwright traces and HTTP request bodies. Keep traces
// disabled for authentication cases; failure screenshots still mask password inputs.
test.use({ trace: 'off' })

test('登录后进入服务大厅并读取用户中心真实 API', async ({ page }) => {
  await page.goto('/login')
  await page.getByTestId('login-email').fill('student50@campus.edu')
  await page.getByTestId('login-password').fill('[REDACTED]')
  const loginResponse = page.waitForResponse(
    (response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST',
  )
  await page.getByTestId('login-submit').click()
  await loginResponse
  if (await page.getByTestId('login-password').isVisible()) {
    await page.getByTestId('login-password').fill('')
  }

  await expect(page).toHaveURL('http://127.0.0.1:4173/')
  await expect(page.getByRole('heading', { name: '服务大厅' })).toBeVisible()

  await page.getByRole('link', { name: '用户中心' }).click()
  await expect(page).toHaveURL(/\/me$/)
  const userCenter = page.getByRole('region', { name: '用户中心' })
  await expect(userCenter.getByText('student50@campus.edu', { exact: true })).toBeVisible()
  await expect(page.getByText('Desktop Chrome')).toBeVisible()
  await expect(page.getByText('1 / 10 封')).toBeVisible()
})

test('连续五次错误口令触发锁定提示且页面不回显口令', async ({ page }) => {
  await page.goto('/login')
  await page.getByTestId('login-email').fill('lockout50@campus.edu')
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await page.getByTestId('login-password').fill('[REDACTED-WRONG]')
    const loginResponse = page.waitForResponse(
      (response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST',
    )
    await page.getByTestId('login-submit').click()
    await loginResponse
    await page.getByTestId('login-password').fill('')
  }

  await expect(page.getByText('登录尝试次数过多，账号可能已暂时锁定，请 10 分钟后再试。')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('[REDACTED-WRONG]')
})
