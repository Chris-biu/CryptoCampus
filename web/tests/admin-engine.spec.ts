import { describe, expect, it } from 'vitest'
import { getEngineDetails, reloadPqcProvider } from '@/api/admin'
import { installApiMock, jsonResponse } from './support/api'

const status = {
  api: 'ok',
  engine: 'online',
  version: '0.2.0',
  tlcp: 'online',
  providers: { 'ML-KEM-768': true, 'ML-DSA-65': false },
}

describe('Issue #47 管理台引擎与 Provider', () => {
  it('读取引擎状态时携带管理员令牌', async () => {
    const mock = installApiMock({ '/api/v1/admin/engine': jsonResponse(status) })
    await getEngineDetails('admin-token')
    expect(((mock.mock.calls[0][1] as RequestInit).headers as Headers).get('Authorization')).toBe(
      'Bearer admin-token',
    )
  })
  it('重载 Provider 使用独立幂等键且不发送配置秘密', async () => {
    const mock = installApiMock({ '/api/v1/admin/providers/reload': jsonResponse(status) })
    await reloadPqcProvider('admin-token', 'reload-47')
    const init = mock.mock.calls[0][1] as RequestInit
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('reload-47')
    expect(init.body).toBeUndefined()
  })
})
