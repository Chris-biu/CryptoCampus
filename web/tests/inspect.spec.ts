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
type InspectRecord = components['schemas']['InspectRecord']

const student: User = {
  id: '00000000-0000-4000-8000-000000000044',
  email: 'student@example.edu.cn',
  role: 'student',
  status: 'active',
  pqc_mode: false,
  created_at: '2026-09-03T00:00:00Z',
}

const inspectRecord: InspectRecord = {
  id: '11111111-1111-4111-8111-111111111111',
  operation: 'drop_extract',
  owner: 'self',
  created_at: '2026-09-03T08:30:00Z',
  steps: [
    {
      order: 1,
      name: 'SM2 解封装',
      algorithm: 'SM2',
      result: 'passed',
      redacted_values: { input_bytes: 256, output_prefix: '9F 27 6E A3 …' },
    },
    {
      order: 2,
      name: 'KDF 合成',
      algorithm: 'HKDF-SM3',
      result: 'passed',
      redacted_values: { duration_ms: 1.8, session_key: 'must-never-render' },
    },
    {
      order: 3,
      name: '完整性校验',
      algorithm: 'SM4-GCM',
      result: 'failed',
      redacted_values: { tag_length: 16, valid: false },
    },
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

function createInspectFetch(options?: {
  detailResponse?: Response
  listResponse?: Response
  metadataResponse?: Response
  reportResponse?: Response
}) {
  return vi.fn().mockImplementation((input: string) => {
    const url = new URL(input, 'http://localhost')
    if (url.pathname.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
    if (url.pathname.endsWith(`/inspect/records/${inspectRecord.id}/report`)) {
      return Promise.resolve(
        options?.reportResponse ??
          new Response('# 脱敏实验报告', { headers: { 'Content-Type': 'text/markdown' } }),
      )
    }
    if (url.pathname.endsWith(`/inspect/records/${inspectRecord.id}`)) {
      return Promise.resolve(options?.detailResponse ?? jsonResponse(inspectRecord))
    }
    if (url.pathname.endsWith('/inspect/records')) {
      return Promise.resolve(
        options?.listResponse ??
          jsonResponse({ items: [inspectRecord], page: 1, page_size: 20, total: 1 }),
      )
    }
    if (url.pathname.endsWith('/admin/inspect-records')) {
      return Promise.resolve(
        options?.metadataResponse ?? jsonResponse({ items: [], page: 1, page_size: 10, total: 0 }),
      )
    }
    return Promise.reject(new Error(`Unexpected request: ${input}`))
  })
}

async function mountInspect(fetchMock = createInspectFetch(), user: User = student) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('test-access-token-redacted', user)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/inspect')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('密码透视记录回放', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    useSessionStore(pinia).clear()
    const security = useSecurityStore(pinia)
    security.setSystemStatus(null)
    security.setPqcEnabled(null)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('按后端顺序展示步骤并支持播放、暂停、单步和失败定位', async () => {
    vi.useFakeTimers()
    const { wrapper } = await mountInspect()

    const steps = wrapper.findAll('.flow-step')
    expect(steps).toHaveLength(3)
    expect(steps[0]?.attributes('aria-current')).toBe('step')

    await wrapper.get('[data-testid="playback-toggle"]').trigger('click')
    expect(wrapper.get('[data-testid="playback-toggle"]').text()).toContain('暂停')
    await vi.advanceTimersByTimeAsync(900)
    expect(wrapper.findAll('.flow-step')[1]?.attributes('aria-current')).toBe('step')

    await wrapper.get('[data-testid="playback-toggle"]').trigger('click')
    expect(wrapper.get('[data-testid="playback-toggle"]').text()).toContain('播放')
    await wrapper.get('button[aria-label="下一步"]').trigger('click')
    expect(wrapper.text()).toContain('当前步骤 3')

    await wrapper.get('button[aria-label="上一步"]').trigger('click')
    await wrapper.get('.failure-locator').trigger('click')
    expect(wrapper.get('.step-detail h3').text()).toBe('完整性校验')
  })

  it('过滤高风险字段并通过后端报告接口导出脱敏素材', async () => {
    const createObjectUrl = vi.fn().mockReturnValue('blob:inspect-report')
    const revokeObjectUrl = vi.fn()
    class MockUrl extends URL {
      static createObjectURL = createObjectUrl
      static revokeObjectURL = revokeObjectUrl
    }
    vi.stubGlobal('URL', MockUrl)
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const { fetchMock, wrapper } = await mountInspect()

    await wrapper.findAll('.flow-step')[1]?.trigger('click')
    expect(wrapper.text()).toContain('1.8 ms')
    expect(wrapper.text()).not.toContain('must-never-render')

    await wrapper.get('.record-actions .el-button').trigger('click')
    await flushPromises()

    expect(
      fetchMock.mock.calls.some(([input]) => String(input).endsWith(`${inspectRecord.id}/report`)),
    ).toBe(true)
    expect(createObjectUrl).toHaveBeenCalledOnce()
    expect(clickSpy).toHaveBeenCalledOnce()
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:inspect-report')
  })

  it('完整呈现空记录、过期与越权状态且不透传后端诊断正文', async () => {
    const emptyFetch = createInspectFetch({
      listResponse: jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }),
    })
    const { wrapper: emptyWrapper } = await mountInspect(emptyFetch)
    expect(emptyWrapper.text()).toContain('暂无可回放的透视记录')

    emptyWrapper.unmount()
    const forbiddenFetch = createInspectFetch({
      detailResponse: jsonResponse(
        { code: 'FORBIDDEN', message: 'sensitive backend detail', request_id: 'request-44' },
        403,
      ),
    })
    const { router, wrapper } = await mountInspect(forbiddenFetch)
    await router.replace(`/inspect/records/${inspectRecord.id}`)
    await flushPromises()
    expect(wrapper.text()).toContain('无权查看这条透视记录')
    expect(wrapper.text()).not.toContain('sensitive backend detail')
  })

  it('学生不请求他人元信息，教师仅看到脱敏元信息列表', async () => {
    const studentRun = await mountInspect()
    expect(studentRun.wrapper.text()).not.toContain('教学审阅元信息')
    expect(
      studentRun.fetchMock.mock.calls.some(([input]) =>
        String(input).includes('/admin/inspect-records'),
      ),
    ).toBe(false)
    studentRun.wrapper.unmount()

    const teacher: User = { ...student, role: 'teacher' }
    const teacherFetch = createInspectFetch({
      metadataResponse: jsonResponse({
        items: [
          {
            id: '22222222-2222-4222-8222-222222222222',
            operation: 'seal_verify',
            owner_user_id: '33333333-3333-4333-8333-333333333333',
            created_at: '2026-09-03T09:00:00Z',
          },
        ],
        page: 1,
        page_size: 10,
        total: 1,
      }),
    })
    const teacherRun = await mountInspect(teacherFetch, teacher)
    expect(teacherRun.wrapper.text()).toContain('教学审阅元信息')
    expect(teacherRun.wrapper.text()).toContain('文件验真')
    expect(teacherRun.wrapper.text()).toContain('用户 33333333…')
  })
})
