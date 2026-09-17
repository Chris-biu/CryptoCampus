import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

const user = {
  id: '00000000-0000-4000-8000-000000000041',
  email: 'student@example.edu.cn',
  role: 'student' as const,
  status: 'active' as const,
  pqc_mode: false,
  created_at: '2026-09-02T00:00:00+08:00',
}

const systemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'openHiTLS-test',
  tlcp: 'online',
  providers: { default: true, pqc: true },
}

const keyring = {
  items: [
    {
      kind: 'sm2_identity',
      algorithm: 'SM2',
      fingerprint: '6E B2 09 4C 1F 88 A0 33',
      status: 'active',
      expires_at: null,
    },
    {
      kind: 'certificate',
      algorithm: 'SM3-with-SM2',
      fingerprint: '9D 41 AA 07 22 C5 E8 10',
      status: 'active',
      expires_at: '2027-08-31T00:00:00Z',
    },
  ],
  unlocked_until: null,
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function createDashboardFetch(options?: {
  keyringResponse?: Response
  pqcResponse?: Response
  systemResponse?: Response
}) {
  return vi.fn().mockImplementation((input: string) => {
    if (input.endsWith('/system/status')) {
      return Promise.resolve(options?.systemResponse ?? jsonResponse(systemStatus))
    }
    if (input.endsWith('/me/keyring')) {
      return Promise.resolve(options?.keyringResponse ?? jsonResponse(keyring))
    }
    if (input.endsWith('/me/pqc-mode')) {
      return Promise.resolve(options?.pqcResponse ?? jsonResponse({ enabled: true }))
    }
    return Promise.reject(new Error(`Unexpected request: ${input}`))
  })
}

async function mountHome(fetchMock = createDashboardFetch(), currentUser = user) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('memory-only-dashboard-token', currentUser)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('服务大厅', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    useSessionStore(pinia).clear()
    const security = useSecurityStore(pinia)
    security.setSystemStatus(null)
    security.setPqcEnabled(null)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('展示六大服务入口、真实系统状态和脱敏密钥环摘要', async () => {
    const { fetchMock, wrapper } = await mountHome()

    expect(wrapper.findAll('.service-card')).toHaveLength(6)
    for (const title of [
      '密信快传',
      '匿名树洞',
      '匿名投票',
      '文件验真',
      '安全聊天',
      '我的密钥环',
    ]) {
      expect(wrapper.text()).toContain(title)
    }
    expect(wrapper.text()).toContain('密码引擎在线')
    expect(wrapper.text()).toContain('openHiTLS-test')
    expect(wrapper.text()).toContain('TLCP 信道')
    expect(wrapper.text()).toContain('6E B2 09 4C 1F 88 A0 33')
    expect(wrapper.text()).toContain('SM3-with-SM2')
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith('/me/keyring'))).toBe(true)
  })

  it('通过契约接口持久化 PQC 偏好并同步会话状态', async () => {
    const { fetchMock, wrapper } = await mountHome()

    await wrapper.get('[data-testid="pqc-switch"] input').setValue(true)
    await flushPromises()

    const pqcCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/me/pqc-mode'))
    expect(pqcCall).toBeDefined()
    expect(pqcCall?.[1]).toEqual(
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({ enabled: true }),
      }),
    )
    expect(useSecurityStore(pinia).pqcEnabled).toBe(true)
    expect(useSessionStore(pinia).currentUser?.pqc_mode).toBe(true)
    expect(wrapper.text()).toContain('PQC 已开启')
  })

  it('PQC 更新失败时回滚开关并隐藏后端诊断正文', async () => {
    const fetchMock = createDashboardFetch({
      pqcResponse: jsonResponse(
        {
          code: 'PROVIDER_UNAVAILABLE',
          message: 'internal provider path must stay hidden',
          request_id: 'request-41',
          details: {},
        },
        503,
      ),
    })
    const { wrapper } = await mountHome(fetchMock)

    await wrapper.get('[data-testid="pqc-switch"] input').setValue(true)
    await flushPromises()

    expect(useSecurityStore(pinia).pqcEnabled).toBe(false)
    expect(useSessionStore(pinia).currentUser?.pqc_mode).toBe(false)
    expect(wrapper.text()).toContain('密码服务暂时不可用')
    expect(wrapper.text()).not.toContain('internal provider path')
  })

  it('服务端明确未接入 PQC 时禁用全局开关', async () => {
    const fetchMock = createDashboardFetch({
      systemResponse: jsonResponse({ ...systemStatus, providers: { default: true, pqc: false } }),
    })
    const { wrapper } = await mountHome(fetchMock)
    expect(wrapper.text()).toContain('PQC 未接入')
    expect(wrapper.get('[data-testid="pqc-switch"] input').attributes('disabled')).toBeDefined()
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/me/pqc-mode'))).toBe(false)
  })

  it('完整展示状态接口不可用和空密钥环场景', async () => {
    const fetchMock = createDashboardFetch({
      systemResponse: jsonResponse(
        { code: 'SERVICE_UNAVAILABLE', message: 'hidden', request_id: 'status-41', details: {} },
        503,
      ),
      keyringResponse: jsonResponse({ items: [], unlocked_until: null }),
    })
    const { wrapper } = await mountHome(fetchMock)

    expect(wrapper.text()).toContain('系统状态暂时不可用')
    expect(wrapper.text()).toContain('不会显示伪造的在线结果')
    expect(wrapper.text()).toContain('当前账号尚无可展示的密钥或证书')
    expect(wrapper.text()).not.toContain('hidden')
  })

  it('密钥环接口未实装时明确显示不可用且不伪造摘要', async () => {
    const fetchMock = createDashboardFetch({
      keyringResponse: jsonResponse(
        {
          code: 'NOT_IMPLEMENTED',
          message: 'backend detail',
          request_id: 'keyring-41',
          details: {},
        },
        501,
      ),
    })
    const { wrapper } = await mountHome(fetchMock)

    expect(wrapper.text()).toContain('密钥环服务暂未开放')
    expect(wrapper.find('.keyring-table').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('backend detail')
  })

  it('只向管理员和教师展示管理入口', async () => {
    const { wrapper } = await mountHome(createDashboardFetch(), {
      ...user,
      role: 'teacher',
    })

    expect(wrapper.get('nav[aria-label="主导航"]').text()).toContain('管理台')
  })
})
