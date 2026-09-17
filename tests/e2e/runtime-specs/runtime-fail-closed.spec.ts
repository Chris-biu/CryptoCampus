import { expect, test } from '@playwright/test'


test('生产 FastAPI 状态在无真实 bridge 时明确显示离线', async ({ page }) => {
  await page.goto('/login')

  await expect(page.getByText('密码引擎离线')).toBeVisible()
  await expect(page.getByText('TLCP 状态未知')).toBeVisible()

  const response = await page.request.get('/api/v1/system/status')
  expect(response.status()).toBe(200)
  await expect(response.json()).resolves.toMatchObject({
    api: 'degraded',
    engine: 'offline',
    tlcp: 'unknown',
    providers: {},
  })
})


test('生产运行时真实投票公开列表正常返回，审计接口对不存在投票返回 404', async ({ page }) => {
  const response = await page.request.get('/api/v1/votes')
  expect(response.status()).toBe(200)
  await expect(response.json()).resolves.toMatchObject({
    items: [],
    total: 0,
    page: 1,
    page_size: 20,
  })

  const auditResponse = await page.request.get(
    '/api/v1/votes/00000000-0000-4000-8000-000000000001/audit',
  )
  expect(auditResponse.status()).toBe(404)
  await expect(auditResponse.json()).resolves.toMatchObject({
    code: 'NOT_FOUND',
    message: '投票不存在或未公开',
  })

  await page.goto('/vote')
  await expect(page.getByRole('heading', { name: '匿名投票' })).toBeVisible()
  await expect(page.getByText('暂无可见投票')).toBeVisible()
})
