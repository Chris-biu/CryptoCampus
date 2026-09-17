/* global HTMLAnchorElement */
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import AdminEngineView from '@/views/admin/AdminEngineView.vue'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { installApiMock, jsonResponse } from './support/api'

const admin = {
  id: 'admin-1', email: 'admin@example.edu.cn', role: 'admin' as const, status: 'active' as const,
  pqc_mode: false, created_at: '2026-09-10T00:00:00Z',
}
const student = {
  id: 'user-1', email: 'student@example.edu.cn', role: 'student' as const, status: 'active' as const,
  pqc_mode: false, created_at: '2026-09-10T00:00:00Z',
}

function button(wrapper: ReturnType<typeof mount>, label: string) {
  return wrapper.findAll('button').find((item) => item.text().includes(label))!
}

describe('管理台交付治理操作', () => {
  beforeEach(() => useSessionStore(pinia).establish('admin-token', admin))

  it('加载用户并执行账号、内容治理和审计导出', async () => {
    const fetchMock = installApiMock({
      '/api/v1/admin/engine': jsonResponse({ api: 'ok', engine: 'online', version: 'test', tlcp: 'online', providers: {} }),
      '/api/v1/admin/users?page=1&page_size=20': jsonResponse({ items: [student], page: 1, page_size: 20, total: 1 }),
      '/api/v1/admin/users/user-1/status': jsonResponse({ ...student, status: 'frozen' }),
      '/api/v1/admin/users/user-1/role': jsonResponse({ ...student, role: 'teacher' }),
      '/api/v1/admin/users/user-1/quotas/reset': jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }),
      '/api/v1/admin/hole/posts/post-1/withdraw': jsonResponse({ sn: 'sn-1' }),
      '/api/v1/admin/drops/drop-1/destroy': new Response(null, { status: 204 }),
      '/api/v1/admin/votes/vote-1/audit-flags': jsonResponse({ accepted: true }, 201),
      '/api/v1/admin/audit/export?format=csv': new Response('action,target'),
    })
    const createObjectURL = vi.fn(() => 'blob:audit')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', class extends URL {
      static createObjectURL = createObjectURL
      static revokeObjectURL = revokeObjectURL
    })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)

    const wrapper = mount(AdminEngineView, { global: { plugins: [pinia] } })
    await flushPromises()
    await button(wrapper, '加载用户').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('student@example.edu.cn')

    const state = wrapper.vm as unknown as {
      userAction: { userId: string; role: string; status: string; reason: string }
      governance: { kind: string; target: string; reason: string }
    }
    state.userAction.userId = 'user-1'
    state.userAction.reason = '课程治理测试'
    state.userAction.status = 'frozen'
    await button(wrapper, '更新状态').trigger('click')
    await flushPromises()
    state.userAction.role = 'teacher'
    await button(wrapper, '更新角色').trigger('click')
    await flushPromises()
    await button(wrapper, '重置额度').trigger('click')
    await flushPromises()

    for (const [kind, target] of [['hole', 'post-1'], ['drop', 'drop-1'], ['vote', 'vote-1']] as const) {
      state.governance.kind = kind
      state.governance.target = target
      state.governance.reason = '违规内容复核'
      await button(wrapper, '执行治理操作').trigger('click')
      await flushPromises()
    }
    await button(wrapper, '导出 CSV').trigger('click')
    await flushPromises()

    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(expect.arrayContaining([
      '/api/v1/admin/users/user-1/status',
      '/api/v1/admin/users/user-1/role',
      '/api/v1/admin/users/user-1/quotas/reset',
      '/api/v1/admin/hole/posts/post-1/withdraw',
      '/api/v1/admin/drops/drop-1/destroy',
      '/api/v1/admin/votes/vote-1/audit-flags',
    ]))
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:audit')
  })
})
