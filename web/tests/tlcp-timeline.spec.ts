import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import type { components } from '@/api/schema'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

type User = components['schemas']['User']
type TlcpHandshake = components['schemas']['TlcpHandshake']

const student: User = {
  id: '00000000-0000-4000-8000-000000000046',
  email: 'student@example.edu.cn',
  role: 'student',
  status: 'active',
  pqc_mode: false,
  created_at: '2026-09-04T00:00:00Z',
}

const handshake: TlcpHandshake = {
  protocol: 'TLCP',
  cipher_suite: 'ECC-SM4-SM3',
  signing_certificate: 'CN=gateway-sign · SM3 8A:19:…',
  encryption_certificate: 'CN=gateway-enc · SM3 C4:72:…',
  messages: [
    'ClientHello · 支持套件 2ms',
    'ServerHello · 选择 ECC-SM4-SM3 3ms',
    '服务端发送签名证书与加密证书',
    '客户端完成密钥交换 7ms',
  ],
}

const systemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'test-version',
  tlcp: 'online',
  providers: { default: true, pqc: true },
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function createTlcpFetch(body: unknown = handshake, status = 200) {
  return vi.fn().mockImplementation((input: string) => {
    const url = new URL(input, 'http://localhost')
    if (url.pathname.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
    if (url.pathname.endsWith('/inspect/tlcp/handshake')) {
      return Promise.resolve(jsonResponse(body, status))
    }
    return Promise.reject(new Error(`Unexpected request: ${input}`))
  })
}

async function mountTimeline(fetchMock = createTlcpFetch()) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('test-access-token-redacted', student)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/inspect/tlcp')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('TLCP 双证书握手时序', () => {
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

  it('从契约接口展示真实来源、密码套件、双证书和脱敏时序', async () => {
    const { fetchMock, wrapper } = await mountTimeline()

    expect(
      fetchMock.mock.calls.some(([input]) => String(input).endsWith('/inspect/tlcp/handshake')),
    ).toBe(true)
    expect(wrapper.text()).toContain('来源：真实 TLCP 网关脱敏接口')
    expect(wrapper.text()).toContain('ECC-SM4-SM3')
    expect(wrapper.text()).toContain('CN=gateway-sign')
    expect(wrapper.text()).toContain('CN=gateway-enc')
    expect(wrapper.text()).toContain('ClientHello')
    expect(wrapper.text()).toContain('接口未提供成功判定，不额外推断')
    expect(wrapper.text()).not.toContain('握手成功')
  })

  it('定位后端摘要明确标记的失败阶段且绝不显示成功', async () => {
    const failedHandshake: TlcpHandshake = {
      ...handshake,
      messages: ['ClientHello', 'ServerHello', 'CertificateVerify：失败（签名不匹配）'],
    }
    const { wrapper } = await mountTimeline(createTlcpFetch(failedHandshake))

    expect(wrapper.text()).toContain('记录含失败阶段')
    expect(wrapper.text()).not.toContain('网关记录已返回')
    await wrapper.get('[data-testid="focus-failure"]').trigger('click')
    expect(wrapper.text()).toContain('当前步骤 3')
    expect(wrapper.text()).toContain('后端摘要明确标记失败')
  })

  it('支持键盘切换步骤并提供完整文本替代', async () => {
    const { wrapper } = await mountTimeline()
    const steps = wrapper.findAll('.timeline-step')
    expect(steps[0]?.attributes('aria-current')).toBe('step')

    await steps[0]?.trigger('keydown', { key: 'ArrowRight' })
    expect(wrapper.findAll('.timeline-step')[1]?.attributes('aria-current')).toBe('step')
    expect(wrapper.get('.text-alternative').text()).toContain('第 1 步')
    expect(wrapper.get('.text-alternative').text()).toContain('第 4 步')
  })

  it('过滤疑似敏感报文并正确呈现空阶段', async () => {
    const redactedHandshake: TlcpHandshake = {
      ...handshake,
      signing_certificate: 'private_key=must-never-render',
      messages: [],
    }
    const { wrapper } = await mountTimeline(createTlcpFetch(redactedHandshake))

    expect(wrapper.text()).toContain('[敏感报文字段已隐藏]')
    expect(wrapper.text()).not.toContain('must-never-render')
    expect(wrapper.text()).toContain('没有可展示的脱敏报文阶段')
  })

  it('权限失败时不使用演示数据替代真实结果', async () => {
    const { wrapper } = await mountTimeline(
      createTlcpFetch({ code: 'FORBIDDEN', message: 'backend permission detail' }, 403),
    )

    expect(wrapper.text()).toContain('当前账号无权读取 TLCP 握手记录')
    expect(wrapper.text()).not.toContain('backend permission detail')
    expect(wrapper.text()).not.toContain('CN=gateway-sign')
  })
})
