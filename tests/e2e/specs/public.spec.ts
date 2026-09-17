import { expect, test } from '@playwright/test'

test('未登录访问受保护桌面端页面会回到登录页', async ({ page }) => {
  await page.goto('/')

  await expect(page).toHaveURL(/\/login\?redirect=/)
  await expect(page.getByRole('heading', { name: '密信校园 CryptoCampus' })).toBeVisible()
  await expect(page.getByText('密码引擎在线')).toBeVisible()
})
