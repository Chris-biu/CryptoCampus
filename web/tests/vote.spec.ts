import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { createVote } from '@/api/votes'
import { installApiMock, jsonResponse } from './support/api'

const vote = {
  id: '30000000-0000-4000-8000-000000000001',
  title: '班委改选',
  options: [
    { id: '40000000-0000-4000-8000-000000000001', label: '王小明' },
    { id: '40000000-0000-4000-8000-000000000002', label: '李华' },
  ],
  scope: 'class',
  status: 'open',
  closes_at: '2026-09-10T14:00:00Z',
}
const result = {
  vote_id: vote.id,
  counts: { [vote.options[0].id]: 21, [vote.options[1].id]: 14 },
  total: 35,
  signature: 'redacted-signature',
  signer_certificate: 'redacted-cert',
  published_at: '2026-09-04T15:00:00Z',
}

async function mountVote(routes: Parameters<typeof installApiMock>[0]) {
  const fetchMock = installApiMock(routes)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/vote')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, wrapper }
}

describe('Issue #24 匿名投票页面', () => {
  beforeEach(() => useSessionStore(pinia).clear())
  afterEach(() => delete window.cryptoCampusCredentialProvider)

  it('游客可查看候选项和签名结果且请求不带身份', async () => {
    const { fetchMock, wrapper } = await mountVote({
      '/api/v1/votes?page=1&page_size=20': jsonResponse({
        items: [vote],
        page: 1,
        page_size: 20,
        total: 1,
      }),
      [`/api/v1/votes/${vote.id}/results`]: jsonResponse(result),
    })
    expect(wrapper.text()).toContain('王小明')
    expect(wrapper.text()).toContain('21')
    const calls = fetchMock.mock.calls.map(([, init]) => init as RequestInit)
    expect(calls.every((init) => !(init.headers as Headers).has('Authorization'))).toBe(true)
  })

  it('在安全客户端适配器接入前禁止伪造匿名选票', async () => {
    const { wrapper } = await mountVote({
      '/api/v1/votes?page=1&page_size=20': jsonResponse({
        items: [vote],
        page: 1,
        page_size: 20,
        total: 1,
      }),
      [`/api/v1/votes/${vote.id}/results`]: jsonResponse(result),
    })
    expect(wrapper.text()).toContain('不得由页面 JavaScript 模拟')
    expect(
      wrapper
        .findAll('button')
        .some(
          (button) =>
            button.text().includes('申领凭证并匿名投票') &&
            button.attributes('disabled') !== undefined,
        ),
    ).toBe(true)
  })

  it('公开验证结果签名', async () => {
    const { wrapper } = await mountVote({
      '/api/v1/votes?page=1&page_size=20': jsonResponse({
        items: [vote],
        page: 1,
        page_size: 20,
        total: 1,
      }),
      [`/api/v1/votes/${vote.id}/results`]: jsonResponse(result),
      [`/api/v1/votes/${vote.id}/results/verify`]: jsonResponse({
        valid: true,
        algorithm: 'SM3-with-SM2',
        certificate_valid: true,
        message: 'raw backend text',
      }),
    })
    const button = wrapper.findAll('button').find((item) => item.text().includes('验证结果签名'))
    await button?.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('结果签名与证书均有效')
    expect(wrapper.text()).not.toContain('raw backend text')
  })

  it('按契约发送创建投票请求、令牌和幂等键', async () => {
    const fetchMock = installApiMock({ '/api/v1/votes': jsonResponse(vote, 201) })
    await createVote(
      {
        title: '班委改选',
        options: [{ label: '王小明' }, { label: '李华' }],
        scope: 'class',
        closes_at: '2026-09-10T14:00:00Z',
      },
      'memory-token',
      'request-24',
    )
    expect(
      fetchMock.mock.calls.some(
        ([url, init]) => url === '/api/v1/votes' && (init as RequestInit).method === 'POST',
      ),
    ).toBe(true)
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect((init.headers as Headers).get('Authorization')).toBe('Bearer memory-token')
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('request-24')
  })

  it('安全凭证组件就绪后签发一次性凭证并提交匿名选票', async () => {
    useSessionStore(pinia).establish('memory-token', {
      id: 'user-1',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-09-10T00:00:00Z',
    })
    window.cryptoCampusCredentialProvider = {
      blind: vi.fn().mockResolvedValue({ blindedMessage: 'blinded-ballot', state: 'opaque' }),
      unblind: vi.fn().mockResolvedValue({
        sn: 'ballot-sn',
        service: 'vote_ballot',
        period: vote.id,
        signature: 'signature',
      }),
    }
    const { fetchMock, wrapper } = await mountVote({
      '/api/v1/votes?page=1&page_size=20': jsonResponse({
        items: [vote],
        page: 1,
        page_size: 20,
        total: 1,
      }),
      [`/api/v1/votes/${vote.id}/results`]: jsonResponse(result),
      [`/api/v1/votes/${vote.id}/credentials/commitments`]: jsonResponse(
        {
          commitment_id: '0123456789abcdef0123456789abcdef',
          commitment_point: 'point-base64',
          signer_public_key: 'public-key-base64',
          expires_at: '2026-09-10T12:10:00Z',
          algorithm: 'SM2-BLIND-PROTOCOL-V1',
        },
        201,
      ),
      [`/api/v1/votes/${vote.id}/credentials`]: jsonResponse(
        { blind_signature: 'blind', algorithm: 'SM2-BLIND-PROTOCOL-V1' },
        201,
      ),
      [`/api/v1/votes/${vote.id}/ballots`]: jsonResponse({ accepted: true }, 201),
    })
    await wrapper.get('.options input').setValue(vote.options[0].id)
    await wrapper.get('[data-testid="submit-ballot"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('匿名选票已接收')
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(
      expect.arrayContaining([
        `/api/v1/votes/${vote.id}/credentials`,
        `/api/v1/votes/${vote.id}/ballots`,
      ]),
    )
    expect(window.cryptoCampusCredentialProvider.blind).toHaveBeenCalledWith(
      expect.objectContaining({ context: vote.options[0].id }),
    )
  })
})
