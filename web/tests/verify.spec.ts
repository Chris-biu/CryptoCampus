import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { beforeEach, describe, expect, it } from 'vitest'

import App from '@/App.vue'
import {
  createSeal,
  downloadSealSidecar,
  verifyFile,
  type Seal,
  type VerificationResult,
} from '@/api/verify'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { installApiMock, jsonResponse } from './support/api'

describe('Issue #27 文件验真', () => {
  beforeEach(() => useSessionStore(pinia).clear())

  it('游客进入公开验真模式', async () => {
    installApiMock({})
    const router = createAppRouter(createMemoryHistory())
    await router.push('/verify')
    const wrapper = mount(App, { global: { plugins: [pinia, router] } })
    await flushPromises()
    expect(wrapper.text()).toContain('文件验真中心')
    expect(wrapper.text()).toContain('上传验真材料')
    expect(wrapper.text()).toContain('全部通过才判定有效')
    expect(wrapper.text()).not.toContain('任一步失败即停止')
    expect(wrapper.text()).toContain('PDF、PNG、JPEG')
  })

  it('选择文本文件时在发请求前给出支持格式提示', async () => {
    const fetchMock = installApiMock({})
    const router = createAppRouter(createMemoryHistory())
    await router.push('/verify')
    const wrapper = mount(App, { global: { plugins: [pinia, router] } })
    await flushPromises()
    const input = wrapper.find('input[type="file"]')
    Object.defineProperty(input.element, 'files', {
      configurable: true,
      value: [new File(['hello'], '原文.txt', { type: 'text/plain' })],
    })
    await input.trigger('change')
    await flushPromises()
    expect(wrapper.text()).toContain('仅支持 PDF、PNG 或 JPEG 文件')
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/verifications'))).toBe(false)
  })

  it('签发请求携带令牌、幂等键和契约字段', async () => {
    const response: Seal = {
      id: '50000000-0000-4000-8000-000000000001',
      digest_algorithm: 'SM3',
      digest: 'test-digest',
      signature_algorithm: 'SM3-with-SM2',
      signature: 'test-signature',
      certificate: 'test-cert',
      timestamp: '2026-09-04T00:00:00Z',
    }
    const fetchMock = installApiMock({ '/api/v1/seals': jsonResponse(response, 201) })
    await createSeal(
      {
        file: new File(['safe'], 'proof.pdf'),
        sealProfile: 'personal',
        pqcMode: false,
        outputFormat: 'sidecar',
      },
      'memory-token',
      'request-27',
    )
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect((init.headers as Headers).get('Authorization')).toBe('Bearer memory-token')
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('request-27')
    expect(init.body).toBeInstanceOf(FormData)
  })

  it('公开验真请求不发送认证令牌', async () => {
    const response: VerificationResult = {
      valid: false,
      steps: [{ name: 'digest', passed: false, message: '文件已篡改' }],
      record_digest: 'test-record',
    }
    const fetchMock = installApiMock({ '/api/v1/verifications': jsonResponse(response) })
    await verifyFile(new File(['changed'], 'proof.pdf'), new File(['seal'], 'proof.seal.json'))
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers
    expect(headers.has('Authorization')).toBe(false)
  })

  it('Sidecar 从服务端正式下载接口取得', async () => {
    const fetchMock = installApiMock({
      '/api/v1/seals/50000000-0000-4000-8000-000000000001/sidecar': () =>
        new Response('{"id":"test"}', { headers: { 'Content-Type': 'application/octet-stream' } }),
    })
    const blob = await downloadSealSidecar('50000000-0000-4000-8000-000000000001')
    expect(await blob.text()).toContain('test')
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/seals/50000000-0000-4000-8000-000000000001/sidecar',
    )
  })
})
