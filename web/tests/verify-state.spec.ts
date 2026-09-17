import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import VerifyView from '@/views/verify/VerifyView.vue'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import type { Seal, VerificationResult } from '@/api/verify'
import { installApiMock, jsonResponse } from './support/api'

const seal: Seal = {
  id: 'test-seal',
  digest_algorithm: 'SM3',
  digest: 'test-digest',
  signature_algorithm: 'SM3-with-SM2',
  signature: 'test-signature',
  certificate: 'test-cert',
  timestamp: '2026-01-01T00:00:00Z',
}
const failed: VerificationResult = {
  valid: false,
  steps: [{ name: 'digest', passed: false, message: '文件摘要不匹配' }],
  record_digest: 'test-record',
}
const passed: VerificationResult = {
  valid: true,
  steps: ['digest', 'signature', 'certificate_chain', 'timestamp', 'revocation'].map((name) => ({
    name: name as VerificationResult['steps'][number]['name'],
    passed: true,
    message: '测试通过',
  })),
  record_digest: 'test-record',
}
const render = () => mount(VerifyView, { global: { plugins: [pinia] } })
async function choose(
  wrapper: ReturnType<typeof render>,
  index: number,
  file = index === 0
    ? new File(['%PDF-1.4\n% test-only\n%%EOF\n'], 'document.pdf', { type: 'application/pdf' })
    : new File(['{"test":true}'], 'document.ccseal', { type: 'application/octet-stream' }),
) {
  const input = wrapper.findAll('input[type="file"]')[index]
  Object.defineProperty(input.element, 'files', { configurable: true, value: [file] })
  await input.trigger('change')
}

describe('验真失败、签发权限与可用凭证', () => {
  beforeEach(() => useSessionStore(pinia).clear())

  it('篡改失败只显示实际执行步骤，不补造后续成功', async () => {
    installApiMock({ '/api/v1/verifications': () => jsonResponse(failed) })
    const wrapper = render()
    await choose(wrapper, 0)
    await choose(wrapper, 1)
    await wrapper.get('.input-panel .el-button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('验真未通过')
    expect(wrapper.findAll('.steps li')).toHaveLength(1)
    expect(wrapper.find('.verdict.valid').exists()).toBe(false)
  })

  it('新请求失败后清除之前的成功结论', async () => {
    let count = 0
    installApiMock({
      '/api/v1/verifications': () =>
        ++count === 1
          ? jsonResponse(passed)
          : jsonResponse({ code: 'UNAVAILABLE', message: 'private-debug' }, 503),
    })
    const wrapper = render()
    await choose(wrapper, 0)
    await choose(wrapper, 1)
    await wrapper.get('.input-panel .el-button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('文件真实且完整')
    await wrapper.get('.input-panel .el-button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('文件真实且完整')
    expect(wrapper.text()).toContain('密码服务暂时不可用')
    expect(wrapper.text()).not.toContain('private-debug')
  })

  it.each([401, 403])('签发接口 %s 不显示成功或下载入口', async (status) => {
    useSessionStore(pinia).establish('test-token', {
      id: 'test-user',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-01-01T00:00:00Z',
    })
    installApiMock({
      '/api/v1/seals': () => jsonResponse({ code: 'DENIED', message: 'private-debug' }, status),
    })
    const wrapper = render()
    await wrapper.findAll('.mode-switch button')[1].trigger('click')
    await choose(wrapper, 0)
    await wrapper.get('.input-panel .el-button').trigger('click')
    await flushPromises()
    expect(wrapper.find('.verdict.valid').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('下载 Sidecar')
    expect(wrapper.text()).not.toContain('private-debug')
  })

  it('大于 100 MiB 的文件不会发起请求', async () => {
    const mock = installApiMock({})
    const wrapper = render()
    const file = new File(['test'], 'huge.pdf')
    Object.defineProperty(file, 'size', { value: 100 * 1024 * 1024 + 1 })
    await choose(wrapper, 1)
    await choose(wrapper, 0, file)
    await flushPromises()
    expect(wrapper.text()).toContain('不能超过 100 MiB')
    await wrapper.get('.input-panel .el-button').trigger('click')
    expect(mock).not.toHaveBeenCalled()
  })

  it('签发后从服务端正式接口下载完整 Sidecar', async () => {
    useSessionStore(pinia).establish('test-token', {
      id: 'test-user',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-01-01T00:00:00Z',
    })
    installApiMock({
      '/api/v1/seals': () => jsonResponse(seal, 201),
      '/api/v1/seals/test-seal/sidecar': () =>
        new Response('{"test":true}', {
          headers: { 'Content-Type': 'application/octet-stream' },
        }),
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
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const wrapper = render()
    await wrapper.findAll('.mode-switch button')[1].trigger('click')
    await choose(wrapper, 0)
    await wrapper.get('.input-panel .el-button').trigger('click')
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '下载 Sidecar 验真凭证')!
      .trigger('click')
    await flushPromises()
    expect(click).toHaveBeenCalledOnce()
    expect(revoke).toHaveBeenCalledWith('blob:test')
    const blob = create.mock.calls[0]![0] as unknown as Blob
    expect(blob).toBeInstanceOf(Blob)
  })
})
