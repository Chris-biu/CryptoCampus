import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

const user = {
  id: '00000000-0000-4000-8000-000000000013',
  email: 'student@example.edu.cn',
  role: 'student' as const,
  status: 'active' as const,
  pqc_mode: false,
  created_at: '2026-09-03T00:00:00+08:00',
}

const createdDrop = {
  id: '13000000-0000-4000-8000-000000000013',
  code: 'kX9mQ2pW',
  access_code: '7H4K-92DM',
  url: '/d/kX9mQ2pW',
  expires_at: null,
  pqc_mode: false,
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

async function mountDropCreate(fetchMock: ReturnType<typeof vi.fn>, pqcMode = false) {
  vi.stubGlobal('fetch', fetchMock)
  useSessionStore(pinia).establish('memory-only-token', { ...user, pqc_mode: pqcMode })
  useSecurityStore(pinia).setPqcEnabled(pqcMode)
  useSecurityStore(pinia).setSystemStatus({
    api: 'ok',
    engine: 'online',
    version: 'openHiTLS-test',
    tlcp: 'online',
    providers: { default: true, pqc: true },
  })
  const router = createAppRouter(createMemoryHistory())
  await router.push('/drop/create')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return wrapper
}

describe('密信快传创建页面', () => {
  beforeEach(() => {
    useSessionStore(pinia).clear()
    useSecurityStore(pinia).setPqcEnabled(null)
    useSecurityStore(pinia).setSystemStatus(null)
    vi.stubGlobal('crypto', { randomUUID: vi.fn(() => 'idempotency-key-13') })
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('按 OpenAPI 字段创建文字密信并展示分离的分享信息', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(createdDrop, 201))
    const wrapper = await mountDropCreate(fetchMock)

    await wrapper.get('[data-testid="drop-content"]').setValue('周四晚七点体育馆见')
    await wrapper.get('[data-testid="drop-password"]').setValue('separate-password')
    await wrapper.get('[data-testid="create-drop"]').trigger('click')
    await flushPromises()

    const request = fetchMock.mock.calls[0]
    expect(request[0]).toBe('/api/v1/drops/text')
    expect(request[1]).toEqual(
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    )
    expect((request[1].headers as Headers).get('Authorization')).toBe('Bearer memory-only-token')
    expect((request[1].headers as Headers).get('Idempotency-Key')).toBe('idempotency-key-13')
    expect(JSON.parse(String(request[1].body))).toEqual({
      content: '周四晚七点体育馆见',
      ttl_policy: 'burn_after_read',
      pqc_mode: false,
      access_password: 'separate-password',
    })
    expect(wrapper.get('[data-testid="result-url"]').text()).toContain('/d/kX9mQ2pW')
    expect(wrapper.get('[data-testid="result-code"]').text()).toBe('7H4K-92DM')
    expect((wrapper.get('[data-testid="drop-password"]').element as HTMLInputElement).value).toBe(
      '',
    )
  })

  it('在抗量子模式下通过 multipart 契约创建文件密信', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        jsonResponse(
          { ...createdDrop, pqc_mode: true, expires_at: '2026-09-04T20:00:00+08:00' },
          201,
        ),
      )
    const wrapper = await mountDropCreate(fetchMock, true)
    const file = new File(['course material'], '课程资料.pdf', { type: 'application/pdf' })

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    Object.defineProperty(wrapper.get('[data-testid="drop-file"]').element, 'files', {
      configurable: true,
      value: [file],
    })
    await wrapper.get('[data-testid="drop-file"]').trigger('change')
    await wrapper.get('[data-testid="create-drop"]').trigger('click')
    await flushPromises()

    const request = fetchMock.mock.calls[0]
    const body = request[1].body as FormData
    expect(request[0]).toBe('/api/v1/drops/file')
    expect(body.get('file')).toBe(file)
    expect(body.get('ttl_policy')).toBe('burn_after_read')
    expect(body.get('pqc_mode')).toBe('true')
    expect(wrapper.text()).toContain('抗量子混合模式')
    expect(wrapper.text()).toContain('SM2 + ML-KEM 双重封装')
  })

  it('在浏览器侧阻止超过 100 MiB 的文件且不发送请求', async () => {
    const fetchMock = vi.fn()
    const wrapper = await mountDropCreate(fetchMock)
    const oversized = new File(['x'], 'oversized.bin')
    Object.defineProperty(oversized, 'size', { value: 100 * 1024 * 1024 + 1 })

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    Object.defineProperty(wrapper.get('[data-testid="drop-file"]').element, 'files', {
      configurable: true,
      value: [oversized],
    })
    await wrapper.get('[data-testid="drop-file"]').trigger('change')
    await wrapper.get('[data-testid="create-drop"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('文件不能超过 100 MiB')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('支持拖放选择并在提交前移除文件', async () => {
    const fetchMock = vi.fn()
    const wrapper = await mountDropCreate(fetchMock)
    const file = new File(['draft'], 'draft.txt', { type: 'text/plain' })
    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    await wrapper.get('.file-dropzone').trigger('drop', {
      dataTransfer: { files: [file] },
    })
    expect(wrapper.text()).toContain('draft.txt')
    await wrapper.get('.remove-file').trigger('click')
    expect(wrapper.text()).not.toContain('draft.txt')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('完整处理空内容且不向接口发送无效请求', async () => {
    const fetchMock = vi.fn()
    const wrapper = await mountDropCreate(fetchMock)

    await wrapper.get('[data-testid="create-drop"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('请输入要分享的文字内容')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('文件过大响应仅展示中文安全错误，不透传后端诊断', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'internal storage path and filename must stay hidden',
          request_id: 'request-13',
          details: {},
        },
        413,
      ),
    )
    const wrapper = await mountDropCreate(fetchMock)
    const file = new File(['small'], 'small.txt')

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    Object.defineProperty(wrapper.get('[data-testid="drop-file"]').element, 'files', {
      configurable: true,
      value: [file],
    })
    await wrapper.get('[data-testid="drop-file"]').trigger('change')
    await wrapper.get('[data-testid="create-drop"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('文件超过当前操作允许的大小')
    expect(wrapper.text()).not.toContain('internal storage path')
  })
})
