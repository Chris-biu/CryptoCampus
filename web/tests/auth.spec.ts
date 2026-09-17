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
  id: '00000000-0000-4000-8000-000000000040',
  email: 'student@example.edu.cn',
  role: 'student' as const,
  status: 'active' as const,
  pqc_mode: false,
  created_at: '2026-09-02T00:00:00+08:00',
}

const authSession = {
  access_token: 'memory-only-access-token',
  token_type: 'bearer' as const,
  expires_in: 7200 as const,
  user,
}

const systemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'openHiTLS-test',
  tlcp: 'online',
  providers: { default: true },
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

async function mountLogin(path = '/login') {
  const router = createAppRouter(createMemoryHistory())
  await router.push(path)
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { router, wrapper }
}

describe('登录注册页面', () => {
  beforeEach(() => {
    setActivePinia(pinia)
    useSessionStore(pinia).clear()
    useSecurityStore(pinia).setSystemStatus(null)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('展示后端返回的引擎版本与 TLCP 状态', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(systemStatus)))

    const { wrapper } = await mountLogin()

    expect(wrapper.text()).toContain('密码引擎在线')
    expect(wrapper.text()).toContain('openHiTLS-test')
    expect(wrapper.text()).toContain('TLCP 在线')
  })

  it('按 OpenAPI 字段登录、只在内存建立会话并返回原目标页', async () => {
    const fetchMock = vi.fn().mockImplementation((input: string) => {
      if (input.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
      if (input.endsWith('/auth/login')) return Promise.resolve(jsonResponse(authSession))
      return Promise.reject(new Error(`Unexpected request: ${input}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem')
    const { router, wrapper } = await mountLogin('/me')

    await wrapper.get('[data-testid="login-email"]').setValue(' Student@Example.edu.cn ')
    await wrapper.get('[data-testid="login-password"]').setValue('not-logged-anywhere')
    await wrapper.get('[data-testid="login-form"]').trigger('submit')
    await flushPromises()

    const loginCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/auth/login'))
    expect(loginCall).toBeDefined()
    expect(JSON.parse(String(loginCall?.[1]?.body))).toEqual({
      email: 'student@example.edu.cn',
      password: 'not-logged-anywhere',
    })
    expect(useSessionStore(pinia).accessToken).toBe('memory-only-access-token')
    expect(storageSpy).not.toHaveBeenCalled()
    expect(router.currentRoute.value.name).toBe('me')
  })

  it('将登录限流状态解释为十分钟锁定提示且不透传后端 message', async () => {
    const fetchMock = vi.fn().mockImplementation((input: string) => {
      if (input.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
      return Promise.resolve(
        jsonResponse(
          {
            code: 'RATE_LIMITED',
            message: 'internal diagnostic should stay hidden',
            request_id: 'request-40',
            details: {},
          },
          429,
        ),
      )
    })
    vi.stubGlobal('fetch', fetchMock)
    const { wrapper } = await mountLogin()

    await wrapper.get('[data-testid="login-email"]').setValue('student@example.edu.cn')
    await wrapper.get('[data-testid="login-password"]').setValue('incorrect')
    await wrapper.get('[data-testid="login-form"]').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('账号可能已暂时锁定')
    expect(wrapper.text()).not.toContain('internal diagnostic')
  })

  it('后端认证接口未实装时明确显示不可用状态', async () => {
    const fetchMock = vi.fn().mockImplementation((input: string) => {
      if (input.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
      return Promise.resolve(jsonResponse({ detail: 'Not Found' }, 404))
    })
    vi.stubGlobal('fetch', fetchMock)
    const { wrapper } = await mountLogin()

    await wrapper.get('[data-testid="login-email"]').setValue('student@example.edu.cn')
    await wrapper.get('[data-testid="login-password"]').setValue('not-a-real-password')
    await wrapper.get('[data-testid="login-form"]').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('认证服务暂未开放')
    expect(wrapper.text()).not.toContain('Not Found')
  })

  it('请求验证码后按契约注册并直接建立认证状态', async () => {
    const fetchMock = vi.fn().mockImplementation((input: string) => {
      if (input.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
      if (input.endsWith('/auth/register/request-code')) {
        return Promise.resolve(jsonResponse({ accepted: true }, 202))
      }
      if (input.endsWith('/auth/register')) return Promise.resolve(jsonResponse(authSession, 201))
      return Promise.reject(new Error(`Unexpected request: ${input}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    const { router, wrapper } = await mountLogin()

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    await wrapper.get('[data-testid="register-email"]').setValue('student@example.edu.cn')
    await wrapper.get('[data-testid="send-code"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('请求已受理')

    await wrapper.get('[data-testid="register-code"]').setValue('123456')
    await wrapper.get('[data-testid="register-password"]').setValue('SecurePass40')
    await wrapper.get('[data-testid="register-confirm-password"]').setValue('SecurePass40')
    await wrapper.get('[data-testid="register-form"]').trigger('submit')
    await flushPromises()

    const registerCall = fetchMock.mock.calls.find(([input]) =>
      String(input).endsWith('/auth/register'),
    )
    expect(JSON.parse(String(registerCall?.[1]?.body))).toEqual({
      email: 'student@example.edu.cn',
      password: 'SecurePass40',
      verification_code: '123456',
    })
    expect(useSessionStore(pinia).isAuthenticated).toBe(true)
    expect(router.currentRoute.value.name).toBe('home')
  })

  it('口令边界或二次确认不一致时不发送注册请求', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(systemStatus))
    vi.stubGlobal('fetch', fetchMock)
    const { wrapper } = await mountLogin()

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    await wrapper.get('[data-testid="register-email"]').setValue('student@example.edu.cn')
    await wrapper.get('[data-testid="register-code"]').setValue('123456')
    await wrapper.get('[data-testid="register-password"]').setValue('weak')
    await wrapper.get('[data-testid="register-confirm-password"]').setValue('different')
    await wrapper.get('[data-testid="register-form"]').trigger('submit')
    await flushPromises()

    await vi.waitFor(() => {
      expect(wrapper.text()).toContain('口令需为 10–128 位')
      expect(wrapper.text()).toContain('两次输入的口令不一致')
    })
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith('/auth/register'))).toBe(
      false,
    )
  })
})

describe('认证会话生命周期', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('使用 HttpOnly Cookie 对应的刷新接口恢复内存会话', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(authSession))
    vi.stubGlobal('fetch', fetchMock)
    const isolatedPinia = createPinia()
    const isolatedSession = useSessionStore(isolatedPinia)

    await isolatedSession.restore()

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/refresh',
      expect.objectContaining({ credentials: 'include', method: 'POST' }),
    )
    expect(isolatedSession.accessToken).toBe('memory-only-access-token')
    expect(isolatedSession.isInitialized).toBe(true)
  })

  it('退出请求即使失败也清理浏览器内存中的认证状态', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { code: 'SESSION_EXPIRED', message: 'hidden', request_id: 'logout-40', details: {} },
            401,
          ),
        ),
    )
    const isolatedPinia = createPinia()
    const isolatedSession = useSessionStore(isolatedPinia)
    isolatedSession.establish(authSession.access_token, authSession.user)

    await expect(isolatedSession.signOut()).rejects.toMatchObject({ status: 401 })

    expect(isolatedSession.accessToken).toBeNull()
    expect(isolatedSession.currentUser).toBeNull()
  })

  it('应用外壳提供退出入口并返回登录页', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })))
    useSessionStore(pinia).establish(authSession.access_token, authSession.user)
    const router = createAppRouter(createMemoryHistory())
    await router.push('/')
    await router.isReady()
    const wrapper = mount(App, { global: { plugins: [pinia, router] } })

    await wrapper.get('[data-testid="logout"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('login')
    expect(useSessionStore(pinia).isAuthenticated).toBe(false)
  })
})
