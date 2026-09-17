import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory } from 'vue-router'
import BenchmarkPanel from '@/views/admin/BenchmarkPanel.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { useSecurityStore } from '@/stores/security'
import type { BenchmarkResult } from '@/api/benchmarks'
import { installApiMock, jsonResponse } from './support/api'

const job = { id: 'test-job', status: 'queued', created_at: '2026-01-01T00:00:00Z' }
const result: BenchmarkResult = { ...job, status: 'running', metrics: [] }
const render = () => mount(BenchmarkPanel, { global: { plugins: [pinia] } })
const auth = (role: 'admin' | 'student' | 'teacher' = 'admin') =>
  useSessionStore(pinia).establish('test-token', {
    id: 'test-user',
    email: 'test@example.edu.cn',
    role,
    status: 'active',
    pqc_mode: false,
    created_at: '2026-01-01T00:00:00Z',
  })
async function start(wrapper: ReturnType<typeof render>) {
  await wrapper
    .findAll('button')
    .find((b) => b.text() === '开始真实性能测试')!
    .trigger('click')
  await flushPromises()
}

describe('独立基准看板的任务生命周期', () => {
  beforeEach(() => auth())
  afterEach(() => vi.useRealTimers())

  it('默认运行课程基线算法，不因未安装 PQC Provider 阻塞真实压测', async () => {
    const mock = installApiMock({
      '/api/v1/admin/benchmarks': () => jsonResponse(job, 202),
      '/api/v1/admin/benchmarks/test-job': () =>
        jsonResponse({ ...result, status: 'completed', metrics: [] }),
    })
    const wrapper = render()
    await start(wrapper)
    const request = mock.mock.calls.find(([, init]) => init?.method === 'POST')?.[1]
    expect(JSON.parse(String(request?.body))).toMatchObject({ include_pqc: false })
    expect(wrapper.text()).toContain('不能计算真实抗量子开销')
    expect(wrapper.text()).not.toContain('抗量子开销 不适用')
  })

  it('只有后端确认真实混合信封能力才允许选择抗量子对比', async () => {
    const security = useSecurityStore(pinia)
    security.setSystemStatus({
      api: 'ok',
      engine: 'online',
      version: 'test',
      tlcp: 'online',
      providers: { hybrid_envelope: true, pqc: true },
    })
    const wrapper = render()
    expect(wrapper.text()).not.toContain('不能计算真实抗量子开销')
    security.setSystemStatus(null)
  })

  it('有限轮询结束后继续查询同一任务，不重复 POST', async () => {
    vi.useFakeTimers()
    let finished = false
    const mock = installApiMock({
      '/api/v1/admin/benchmarks': () => jsonResponse(job, 202),
      '/api/v1/admin/benchmarks/test-job': () =>
        jsonResponse({
          ...result,
          status: finished ? 'completed' : 'running',
          metrics: finished
            ? [{ operation: 'SM3', mean_ms: 1, p99_ms: 2, pqc_overhead_percent: null }]
            : [],
        }),
    })
    const wrapper = render()
    await start(wrapper)
    await vi.advanceTimersByTimeAsync(14000)
    await flushPromises()
    expect(wrapper.text()).toContain('任务仍在运行')
    finished = true
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '继续查询当前任务')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('P99 2.00 ms')
    expect(mock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1)
  })

  it('卸载后停止轮询', async () => {
    vi.useFakeTimers()
    const mock = installApiMock({
      '/api/v1/admin/benchmarks': () => jsonResponse(job, 202),
      '/api/v1/admin/benchmarks/test-job': () => jsonResponse(result),
    })
    const wrapper = render()
    await start(wrapper)
    const count = mock.mock.calls.length
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(20000)
    expect(mock).toHaveBeenCalledTimes(count)
  })

  it.each([401, 403, 503])('请求失败 %s 不显示指标或允许导出', async (status) => {
    installApiMock({
      '/api/v1/admin/benchmarks': () =>
        jsonResponse({ code: 'FAILED', message: 'private-debug' }, status),
    })
    const wrapper = render()
    await start(wrapper)
    expect(wrapper.find('.metrics').exists()).toBe(false)
    expect(
      wrapper.findAll('footer button').every((b) => b.attributes('disabled') !== undefined),
    ).toBe(true)
    expect(wrapper.text()).not.toContain('private-debug')
  })

  it('退出账号后清除数据并停止查询', async () => {
    vi.useFakeTimers()
    const mock = installApiMock({
      '/api/v1/admin/benchmarks': () => jsonResponse(job, 202),
      '/api/v1/admin/benchmarks/test-job': () => jsonResponse(result),
    })
    const wrapper = render()
    await start(wrapper)
    const count = mock.mock.calls.length
    useSessionStore(pinia).clear()
    await flushPromises()
    await vi.advanceTimersByTimeAsync(20000)
    expect(mock).toHaveBeenCalledTimes(count)
    expect(wrapper.text()).not.toContain('test-job')
  })

  it.each(['student', 'guest'] as const)('独立路由阻止 %s 访问', async (role) => {
    if (role === 'guest') useSessionStore(pinia).clear()
    else auth(role)
    const router = createAppRouter(createMemoryHistory())
    await router.push('/admin/benchmarks')
    expect(router.currentRoute.value.name).toBe(role === 'guest' ? 'login' : 'forbidden')
  })

  it('教师可直接访问独立基准页面', async () => {
    auth('teacher')
    const router = createAppRouter(createMemoryHistory())
    await router.push('/admin/benchmarks')
    expect(router.currentRoute.value.name).toBe('admin-benchmarks')
  })
  it('导出 CSV 与 JSON 保留真实指标和引号，释放下载地址', async () => {
    const completed: BenchmarkResult = {
      ...result,
      status: 'completed',
      metrics: [
        { operation: 'SM3,"test"', mean_ms: 1.25, p99_ms: 2.5, pqc_overhead_percent: null },
      ],
    }
    installApiMock({
      '/api/v1/admin/benchmarks': () => jsonResponse(job, 202),
      '/api/v1/admin/benchmarks/test-job': () => jsonResponse(completed),
    })
    const create = vi.fn<(blob: Blob) => string>(() => 'blob:test')
    const revoke = vi.fn()
    vi.stubGlobal(
      'URL',
      class extends URL {
        static createObjectURL = create
        static revokeObjectURL = revoke
      },
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const wrapper = render()
    await start(wrapper)
    await wrapper.findAll('footer button')[0].trigger('click')
    await wrapper.findAll('footer button')[1].trigger('click')
    const read = (blob: Blob) =>
      new Promise<string>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(String(reader.result))
        reader.readAsText(blob)
      })
    expect(await read(create.mock.calls[0]![0])).toContain('"SM3,""test""","1.25","2.5",""')
    expect(JSON.parse(await read(create.mock.calls[1]![0]))).toEqual(completed)
    expect(revoke).toHaveBeenCalledTimes(2)
  })
})
