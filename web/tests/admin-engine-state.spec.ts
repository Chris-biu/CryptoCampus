import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it } from 'vitest'
import AdminEngineView from '@/views/admin/AdminEngineView.vue'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import type { SystemStatus } from '@/api/admin'
import { installApiMock, jsonResponse } from './support/api'

const status: SystemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'test-version',
  tlcp: 'unknown',
  providers: { default: true, pqc: false },
}
const render = () => mount(AdminEngineView, { global: { plugins: [pinia] } })
describe('引擎管理错误状态', () => {
  beforeEach(() => {
    useSessionStore(pinia).establish('test-token', {
      id: 'test-admin',
      email: 'admin@example.edu.cn',
      role: 'admin',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-01-01T00:00:00Z',
    })
  })

  it.each([401, 403, 503])('重载失败 %s 保留最近一次已确认状态', async (httpStatus) => {
    installApiMock({
      '/api/v1/admin/engine': () => jsonResponse(status),
      '/api/v1/admin/providers/reload': () =>
        jsonResponse({ code: 'FAILED', message: 'private-debug' }, httpStatus),
    })
    const wrapper = render()
    await flushPromises()
    expect(wrapper.text()).toContain('引擎在线')
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '重新加载 PQC Provider')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('引擎在线')
    expect(wrapper.text()).not.toContain('private-debug')
    expect(wrapper.text()).not.toContain('暂无引擎状态')
  })

  it('离线状态按后端响应显示，不推断在线', async () => {
    installApiMock({ '/api/v1/admin/engine': () => jsonResponse({ ...status, engine: 'offline' }) })
    const wrapper = render()
    await flushPromises()
    expect(wrapper.text()).toContain('引擎离线')
    expect(wrapper.text()).not.toContain('引擎在线')
  })

  it('状态刷新未完成时禁止重载，避免旧响应覆盖新状态', async () => {
    installApiMock({ '/api/v1/admin/engine': () => new Promise<Response>(() => {}) })
    const wrapper = render()
    await flushPromises()
    const button = wrapper.findAll('button').find((b) => b.text() === '重新加载 PQC Provider')!
    expect(button.attributes('disabled')).toBeDefined()
  })
})
