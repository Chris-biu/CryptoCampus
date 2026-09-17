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
  id: '00000000-0000-4000-8000-000000000042',
  email: 'student@example.edu.cn',
  role: 'student' as const,
  status: 'active' as const,
  pqc_mode: true,
  created_at: '2026-08-20T00:00:00Z',
}

const keyring = {
  items: [
    {
      kind: 'sm2_identity' as const,
      algorithm: 'SM2',
      fingerprint: '6E B2 09 4C 1F 88 A0 33',
      status: 'active' as const,
      expires_at: null,
    },
    {
      kind: 'certificate' as const,
      algorithm: 'SM3-with-SM2',
      fingerprint: '9D 41 AA 07 22 C5 E8 10',
      status: 'active' as const,
      expires_at: '2027-08-31T00:00:00Z',
    },
  ],
  unlocked_until: '2026-09-03T12:15:00Z',
}

const deviceSessions = {
  items: [
    {
      id: '00000000-0000-4000-8000-000000000101',
      device: 'Chrome · Windows',
      ip_masked: '10.2x.x.x',
      last_active_at: '2026-09-03T11:59:30Z',
      current: true,
    },
    {
      id: '00000000-0000-4000-8000-000000000102',
      device: 'Safari · iPhone',
      ip_masked: '10.3x.x.x',
      last_active_at: '2026-09-03T09:00:00Z',
      current: false,
    },
  ],
}

const quotaResponse = {
  items: [
    { resource: 'hole_credential' as const, used: 2, limit: 5 },
    { resource: 'interaction_credential' as const, used: 8, limit: 20 },
    { resource: 'drop' as const, used: 3, limit: 20 },
    { resource: 'vote_ballot' as const, used: 0, limit: 1 },
  ],
  resets_at: '2026-09-04T00:00:00+08:00',
}

const systemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'openHiTLS-test',
  tlcp: 'online',
  providers: { default: true, pqc: true },
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function emptyResponse(status = 204): Response {
  return new Response(null, { status })
}

function createMeFetch(options?: { quotasResponse?: Response; rotationResponse?: Response }) {
  return vi.fn().mockImplementation((input: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (input.endsWith('/system/status')) return Promise.resolve(jsonResponse(systemStatus))
    if (input.endsWith('/me') && method === 'GET') return Promise.resolve(jsonResponse(user))
    if (input.endsWith('/me/password') && method === 'PATCH')
      return Promise.resolve(emptyResponse())
    if (input.endsWith('/me/keyring') && method === 'GET')
      return Promise.resolve(jsonResponse(keyring))
    if (input.endsWith('/me/certificate/verify') && method === 'GET')
      return Promise.resolve(
        jsonResponse({
          valid: true,
          state: 'active',
          serial: 'cert-active',
          verified_at: '2026-09-17T00:00:00Z',
        }),
      )
    if (input.endsWith('/me/keyring/rotate') && method === 'POST') {
      return Promise.resolve(options?.rotationResponse ?? jsonResponse(keyring))
    }
    if (input.endsWith('/me/keyring/export') && method === 'POST') {
      return Promise.resolve(
        new Response('PEM', { headers: { 'Content-Type': 'application/x-pem-file' } }),
      )
    }
    if (input.endsWith('/me/keyring/import') && method === 'POST') {
      return Promise.resolve(jsonResponse(keyring))
    }
    if (input.endsWith('/me/account') && method === 'DELETE') {
      return Promise.resolve(jsonResponse({ accepted: true }, 202))
    }
    if (input.endsWith('/me/sessions') && method === 'GET') {
      return Promise.resolve(jsonResponse(deviceSessions))
    }
    if (input.includes('/me/sessions/') && method === 'DELETE')
      return Promise.resolve(emptyResponse())
    if (input.endsWith('/me/quotas') && method === 'GET') {
      return Promise.resolve(options?.quotasResponse ?? jsonResponse(quotaResponse))
    }
    return Promise.reject(new Error(`Unexpected request: ${method} ${input}`))
  })
}

async function mountMe(fetchMock = createMeFetch()) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('memory-only-user-center-token', user)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/me')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('用户中心', () => {
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

  it('按照 P11 展示账户、密钥环、会话、额度与隐私边界', async () => {
    const { wrapper } = await mountMe()

    expect(wrapper.text()).toContain('student@example.edu.cn')
    expect(wrapper.text()).toContain('学生用户')
    expect(wrapper.text()).toContain('SM2 身份密钥')
    expect(wrapper.text()).toContain('6E B2 09 4C 1F 88 A0 33')
    expect(wrapper.text()).toContain('Chrome · Windows')
    expect(wrapper.text()).toContain('当前设备')
    expect(wrapper.text()).toContain('树洞凭证申领')
    expect(wrapper.text()).toContain('2 / 5 张')
    expect(wrapper.text()).toContain('口令、KEK、私钥明文')
    expect(wrapper.text()).toContain('持久化层不保存明文')
    expect(wrapper.findAll('[data-testid="revoke-session"]')).toHaveLength(1)

    expect(wrapper.get('[data-testid="open-backup-export"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.get('[data-testid="open-backup-import"]').attributes('disabled')).toBeUndefined()
    expect(
      wrapper.get('[data-testid="open-account-deletion"]').attributes('disabled'),
    ).toBeUndefined()
    expect(wrapper.get('[data-testid="verify-certificate"]').attributes('disabled')).toBeUndefined()
  })

  it('通过真实契约验证当前用户证书链', async () => {
    const { fetchMock, wrapper } = await mountMe()

    await wrapper.get('[data-testid="verify-certificate"]').trigger('click')
    await flushPromises()

    expect(
      fetchMock.mock.calls.some(([input]) => String(input).endsWith('/me/certificate/verify')),
    ).toBe(true)
    expect(wrapper.text()).toContain('证书链、有效期与吊销状态验证通过')
  })

  it('校验并通过契约接口修改口令，完成后清空口令字段', async () => {
    const { fetchMock, wrapper } = await mountMe()

    await wrapper.get('.me-form').trigger('submit')
    expect(wrapper.text()).toContain('请输入当前口令')

    await wrapper.get('[data-testid="current-password"]').setValue('OldPassword1')
    await wrapper.get('[data-testid="new-password"]').setValue('NewPassword2')
    await wrapper.get('[data-testid="confirm-password"]').setValue('NewPassword2')
    await wrapper.get('.me-form').trigger('submit')
    await flushPromises()

    const call = fetchMock.mock.calls.find(
      ([input, init]) => String(input).endsWith('/me/password') && init?.method === 'PATCH',
    )
    expect(call?.[1]).toEqual(
      expect.objectContaining({
        body: JSON.stringify({
          current_password: 'OldPassword1',
          new_password: 'NewPassword2',
        }),
      }),
    )
    expect(wrapper.text()).toContain('公钥与证书保持不变')
    expect(wrapper.get('[data-testid="current-password"]').element).toHaveProperty('value', '')
    expect(wrapper.get('[data-testid="new-password"]').element).toHaveProperty('value', '')
  })

  it('密钥轮换必须完成风险确认，并发送幂等键而不暴露口令', async () => {
    const fetchMock = createMeFetch()
    const { wrapper } = await mountMe(fetchMock)

    await wrapper.get('[data-testid="open-rotation"]').trigger('click')
    expect(wrapper.get('[data-testid="confirm-rotation"]').attributes('disabled')).toBeDefined()

    await wrapper.get('[data-testid="rotation-password"]').setValue('OldPassword1')
    await wrapper.get('[data-testid="rotation-acknowledgement"] input').setValue(true)
    await wrapper.get('[data-testid="confirm-rotation"]').trigger('click')
    await flushPromises()

    const call = fetchMock.mock.calls.find(
      ([input, init]) => String(input).endsWith('/me/keyring/rotate') && init?.method === 'POST',
    )
    const headers = call?.[1]?.headers as Headers
    expect(headers.get('Idempotency-Key')).toHaveLength(36)
    expect(call?.[1]?.body).toBe(
      JSON.stringify({ password: 'OldPassword1', acknowledge_inflight_loss: true }),
    )
    expect(wrapper.text()).toContain('密钥环已重新生成')
    expect(wrapper.text()).not.toContain('OldPassword1')
  })

  it('确认后远程登出非当前设备并保留当前设备', async () => {
    const { fetchMock, wrapper } = await mountMe()

    await wrapper.get('[data-testid="revoke-session"]').trigger('click')
    expect(wrapper.text()).toContain('确认远程登出“Safari · iPhone”')
    await wrapper.get('[data-testid="confirm-revoke"]').trigger('click')
    await flushPromises()

    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).endsWith('/me/sessions/00000000-0000-4000-8000-000000000102') &&
          init?.method === 'DELETE',
      ),
    ).toBe(true)
    expect(wrapper.text()).toContain('Chrome · Windows')
    expect(wrapper.find('.sessions-table').text()).not.toContain('Safari · iPhone')
    expect(wrapper.text()).toContain('已远程登出')
  })

  it('单个接口未实现时保留其他真实模块且不显示后端诊断正文', async () => {
    const fetchMock = createMeFetch({
      quotasResponse: jsonResponse(
        {
          code: 'NOT_IMPLEMENTED',
          message: 'internal quota table must stay hidden',
          request_id: 'request-42',
          details: {},
        },
        501,
      ),
    })
    const { wrapper } = await mountMe(fetchMock)

    expect(wrapper.text()).toContain('服务额度暂不可用：此功能暂未开放')
    expect(wrapper.text()).toContain('SM2 身份密钥')
    expect(wrapper.text()).toContain('Chrome · Windows')
    expect(wrapper.text()).not.toContain('internal quota table must stay hidden')
  })

  it('导出和导入口令加密的密钥环备份', async () => {
    const createObjectURL = vi.fn(() => 'blob:keyring')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal(
      'URL',
      class extends URL {
        static createObjectURL = createObjectURL
        static revokeObjectURL = revokeObjectURL
      },
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    const { fetchMock, wrapper } = await mountMe()

    await wrapper.get('[data-testid="open-backup-export"]').trigger('click')
    await wrapper.get('[data-testid="backup-password"]').setValue('BackupPassword1')
    await wrapper.get('[data-testid="submit-backup"]').trigger('click')
    await flushPromises()
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:keyring')

    await wrapper.get('[data-testid="open-backup-import"]').trigger('click')
    await wrapper.get('[data-testid="backup-password"]').setValue('BackupPassword1')
    const fileInput = wrapper.get('[data-testid="backup-file"]')
    Object.defineProperty(fileInput.element, 'files', { value: [new File(['PEM'], 'backup.pem')] })
    await fileInput.trigger('change')
    await wrapper.get('[data-testid="submit-backup"]').trigger('click')
    await flushPromises()

    expect(
      fetchMock.mock.calls.some(([input]) => String(input).endsWith('/me/keyring/import')),
    ).toBe(true)
    expect(wrapper.text()).toContain('密钥环已从加密备份恢复')
  })

  it('账号注销要求口令和固定确认短语，成功后清除登录态', async () => {
    const { fetchMock, router, wrapper } = await mountMe()
    await wrapper.get('[data-testid="open-account-deletion"]').trigger('click')
    await wrapper.get('[data-testid="deletion-password"]').setValue('Password1')
    await wrapper.get('[data-testid="deletion-confirmation"]').setValue('DELETE_MY_ACCOUNT')
    await wrapper.get('[data-testid="confirm-account-deletion"]').trigger('click')
    await flushPromises()

    const call = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/me/account'))
    expect(call?.[1]).toEqual(
      expect.objectContaining({
        method: 'DELETE',
        body: JSON.stringify({ password: 'Password1', confirm: 'DELETE_MY_ACCOUNT' }),
      }),
    )
    expect(useSessionStore(pinia).isAuthenticated).toBe(false)
    expect(router.currentRoute.value.name).toBe('login')
  })

  it('高风险操作可以在提交前安全取消', async () => {
    const { wrapper } = await mountMe()

    await wrapper.get('[data-testid="open-rotation"]').trigger('click')
    await wrapper.get('.danger-confirmation .danger-confirmation-actions button').trigger('click')
    expect(wrapper.find('[data-testid="rotation-password"]').exists()).toBe(false)

    await wrapper.get('[data-testid="revoke-session"]').trigger('click')
    await wrapper.get('.inline-confirmation button').trigger('click')
    expect(wrapper.find('.inline-confirmation').exists()).toBe(false)

    await wrapper.get('[data-testid="open-backup-export"]').trigger('click')
    const dialog = wrapper.findComponent({ name: 'ElDialog' })
    await dialog
      .findAll('button')
      .find((item) => item.text() === '取消')!
      .trigger('click')
    expect(wrapper.findComponent({ name: 'ElDialog' }).props('modelValue') as boolean).toBe(false)
  })
})
