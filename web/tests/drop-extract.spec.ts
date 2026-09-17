import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { installApiMock, jsonResponse } from './support/api'

const metadata = {
  code: 'kX9mQ2pW',
  kind: 'text' as const,
  status: 'available' as const,
  requires_password: true,
  burn_after_read: true,
  filename: null,
  size: null,
  expires_at: null,
}

async function mountPage(routes: Parameters<typeof installApiMock>[0]) {
  const fetchMock = installApiMock(routes)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/d/kX9mQ2pW')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, router, wrapper }
}

describe('Issue #14 密信提取页', () => {
  beforeEach(() => {
    useSessionStore(pinia).clear()
    vi.stubGlobal('crypto', { randomUUID: () => 'extract-idempotency-key' })
  })

  it('公开读取元数据且不发送认证令牌', async () => {
    const { fetchMock, wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse(metadata),
    })

    expect(wrapper.text()).toContain('有人给你发来一封密信')
    expect(wrapper.text()).toContain('首次成功提取后销毁')
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect((init.headers as Headers).has('Authorization')).toBe(false)
  })

  it('提交敏感字段后立即清空并只展示明确通过验证的文字内容', async () => {
    let capturedBody = ''
    let capturedHeaders = new Headers()
    const { fetchMock, wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse(metadata),
      '/api/v1/drops/kX9mQ2pW/extract': ({ init }) => {
        capturedBody = String(init?.body)
        capturedHeaders = init?.headers as Headers
        return jsonResponse({
          kind: 'text',
          content: '周四晚七点在体育馆见。',
          signature_valid: true,
          certificate_valid: true,
          inspect_record_id: '90000000-0000-4000-8000-000000000014',
        })
      },
    })

    await wrapper.get('#extract-code').setValue('7h4k-92dm')
    await wrapper.get('#extract-password').setValue('temporary-password')
    await wrapper.get('form').trigger('submit')

    expect((wrapper.get('#extract-code').element as HTMLInputElement).value).toBe('')
    expect((wrapper.get('#extract-password').element as HTMLInputElement).value).toBe('')
    await flushPromises()
    expect(JSON.parse(capturedBody)).toEqual({
      access_code: '7H4K-92DM',
      access_password: 'temporary-password',
    })
    expect(capturedHeaders.get('Idempotency-Key')).toBe('extract-idempotency-key')
    expect(capturedHeaders.has('Authorization')).toBe(false)
    expect(wrapper.text()).toContain('周四晚七点在体育馆见。')
    expect(wrapper.text()).toContain('发送者签名')
    expect(wrapper.text()).toContain('已经提取')
    expect(wrapper.text()).not.toContain('等待提取')
    expect(wrapper.get('[data-testid="extract-submit"]').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('周四晚七点在体育馆见。')
  })

  it('非阅后即焚密信成功后仍允许在有效期内再次提取', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse({
        ...metadata,
        requires_password: false,
        burn_after_read: false,
      }),
      '/api/v1/drops/kX9mQ2pW/extract': jsonResponse({
        kind: 'text',
        content: '可重复提取的文字',
        signature_valid: true,
        certificate_valid: true,
        inspect_record_id: '90000000-0000-4000-8000-000000000014',
      }),
    })

    await wrapper.get('#extract-code').setValue('7H4K-92DM')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('可重复提取的文字')
    expect(wrapper.text()).not.toContain('已经提取')
    expect(wrapper.get('[data-testid="extract-submit"]').attributes('disabled')).toBeUndefined()
  })

  it('签名或证书未通过时不展示接口返回内容', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse({ ...metadata, requires_password: false }),
      '/api/v1/drops/kX9mQ2pW/extract': jsonResponse({
        kind: 'text',
        content: 'must-never-render',
        signature_valid: false,
        certificate_valid: true,
        inspect_record_id: '90000000-0000-4000-8000-000000000014',
      }),
    })

    await wrapper.get('#extract-code').setValue('7H4K-92DM')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('内容已停止展示')
    expect(wrapper.text()).not.toContain('must-never-render')
    expect(wrapper.text()).not.toContain('已经提取')
  })

  it('错误尝试过多时展示安全冷却提示且不透传后端诊断', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse({ ...metadata, requires_password: false }),
      '/api/v1/drops/kX9mQ2pW/extract': jsonResponse(
        { code: 'INTERNAL_DROP_SECRET', message: 'raw backend detail' },
        429,
      ),
    })

    await wrapper.get('#extract-code').setValue('7H4K-92DM')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('链接已进入安全冷却')
    expect(wrapper.text()).not.toContain('raw backend detail')
    expect(wrapper.text()).not.toContain('INTERNAL_DROP_SECRET')
  })

  it.each([
    ['consumed', '已经提取'],
    ['expired', '已经过期'],
    ['destroyed', '已经销毁'],
    ['cooling_down', '安全冷却中'],
  ] as const)('状态为 %s 时禁止再次提交', async (status, label) => {
    const { wrapper } = await mountPage({
      '/api/v1/drops/kX9mQ2pW': jsonResponse({ ...metadata, status }),
    })

    expect(wrapper.text()).toContain(label)
    expect(wrapper.get('[data-testid="extract-submit"]').attributes('disabled')).toBeDefined()
  })
})
