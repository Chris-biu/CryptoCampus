import { setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'

import { apiClient } from '@/api/client'
import { pinia } from '@/stores'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

import { installApiMock, jsonResponse } from './support/api'
import { authSession, onlineSystemStatus } from './support/fixtures'

describe('前端状态管理', () => {
  beforeEach(() => {
    setActivePinia(pinia)
    useSessionStore(pinia).clear()
    const security = useSecurityStore(pinia)
    security.setSystemStatus(null)
    security.setPqcEnabled(null)
  })

  it('仅在内存中建立并清理认证会话', () => {
    const session = useSessionStore(pinia)

    session.establish(authSession.access_token, authSession.user)

    expect(session.isAuthenticated).toBe(true)
    expect(session.currentUser).toEqual(authSession.user)

    session.clear()

    expect(session.accessToken).toBeNull()
    expect(session.currentUser).toBeNull()
  })

  it('通过契约接口加载密码引擎状态', async () => {
    const fetchMock = installApiMock({
      '/api/v1/system/status': jsonResponse(onlineSystemStatus),
    })
    const security = useSecurityStore(pinia)

    await security.loadSystemStatus()

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(security.engineOnline).toBe(true)
    expect(security.statusLabel).toBe('密码引擎在线')
  })

  it('未声明的 API 请求在测试进程内失败，不访问真实后端', async () => {
    installApiMock({})

    await expect(apiClient.get('/system/status')).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
      status: 0,
    })
  })
})
