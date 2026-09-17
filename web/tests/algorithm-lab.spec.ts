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

const student: User = {
  id: '00000000-0000-4000-8000-000000000045',
  email: 'student@example.edu.cn',
  role: 'student',
  status: 'active',
  pqc_mode: false,
  created_at: '2026-09-04T00:00:00Z',
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

function createExperimentFetch(result?: unknown, status = 200) {
  return vi.fn().mockImplementation((input: string) => {
    const url = new URL(input, 'http://localhost')
    if (url.pathname.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
    if (url.pathname.endsWith('/inspect/experiments')) {
      return Promise.resolve(
        jsonResponse(
          result ?? {
            experiment: 'sm4_mode_compare',
            passed: true,
            steps: ['后端生成教学专用参数', '比较脱敏输出结构'],
            redacted_values: {
              mode: 'ECB / CBC / GCM',
              output_prefix: 'A1 2B …',
              session_key: 'must-never-render',
            },
          },
          status,
        ),
      )
    }
    return Promise.reject(new Error(`Unexpected request: ${input}`))
  })
}

async function mountLab(fetchMock = createExperimentFetch()) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('test-access-token-redacted', student)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/inspect/experiments')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('SM4/SM3 通用算法试验台', () => {
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

  it('清晰警示 ECB 并仅通过契约接口运行 SM4 模式对比', async () => {
    const { fetchMock, wrapper } = await mountLab()
    expect(wrapper.text()).toContain('ECB 风险对照 · 仅限教学')
    expect(wrapper.text()).not.toContain('ECB 仅用于风险教学，绝不是推荐方案')

    await wrapper.get('[data-testid="run-experiment"]').trigger('click')
    await flushPromises()

    const request = fetchMock.mock.calls.find(([input]) =>
      String(input).endsWith('/inspect/experiments'),
    )
    expect(request).toBeTruthy()
    expect(JSON.parse(String(request?.[1]?.body))).toMatchObject({ experiment: 'sm4_mode_compare' })
    expect(wrapper.text()).toContain('后端判定：试验通过')
    expect(wrapper.text()).toContain('ECB / CBC / GCM')
    expect(wrapper.text()).not.toContain('must-never-render')
  })

  it('切换到 SM3 后展示后端提供的摘要翻转统计', async () => {
    const fetchMock = createExperimentFetch({
      experiment: 'sm3_avalanche',
      passed: true,
      steps: ['后端翻转输入中的一个比特', '对比两份 SM3 摘要'],
      redacted_values: { changed_bits: 131, total_bits: 256, digest_prefix: '66c7… / a108…' },
    })
    const { wrapper } = await mountLab(fetchMock)

    await wrapper.get('[data-testid="mode-sm3"]').trigger('click')
    await wrapper.get('[data-testid="run-experiment"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-testid="avalanche-meter"]').text()).toContain('131 / 256 bit')
    expect(wrapper.text()).toContain('统计值由后端提供')
    expect(wrapper.text()).not.toContain('ECB 仅用于风险教学，绝不是推荐方案')
  })

  it('对引擎不可用给出稳定中文错误且不透传后端正文', async () => {
    const { wrapper } = await mountLab(
      createExperimentFetch(
        { code: 'ENGINE_UNAVAILABLE', message: 'private engine stack trace' },
        503,
      ),
    )

    await wrapper.get('[data-testid="run-experiment"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('密码引擎暂不可用')
    expect(wrapper.text()).not.toContain('private engine stack trace')
  })

  it('导出只包含脱敏结果且不写入教学输入或敏感字段', async () => {
    const createObjectUrl = vi.fn().mockReturnValue('blob:algorithm-report')
    const revokeObjectUrl = vi.fn()
    class MockUrl extends URL {
      static createObjectURL = createObjectUrl
      static revokeObjectURL = revokeObjectUrl
    }
    vi.stubGlobal('URL', MockUrl)
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const { wrapper } = await mountLab()

    await wrapper.get('[data-testid="run-experiment"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="export-report"]').trigger('click')

    expect(createObjectUrl).toHaveBeenCalledOnce()
    expect(clickSpy).toHaveBeenCalledOnce()
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:algorithm-report')
  })

  it('可填入教学示例并清空重置', async () => {
    const { wrapper } = await mountLab()
    const textarea = wrapper.get('textarea')
    await wrapper
      .findAll('button')
      .find((item) => item.text() === '使用示例')!
      .trigger('click')
    expect((textarea.element as HTMLTextAreaElement).value.length).toBeGreaterThan(0)
    await wrapper
      .findAll('button')
      .find((item) => item.text() === '清空重置')!
      .trigger('click')
    expect((textarea.element as HTMLTextAreaElement).value).toBe('')
  })
})
