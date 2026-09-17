import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import VoteView from '@/views/vote/VoteView.vue'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import type { Vote, VoteResult } from '@/api/votes'
import { installApiMock, jsonResponse } from './support/api'

const vote = (id: string): Vote => ({
  id,
  title: `议题 ${id}`,
  options: [
    { id: 'a', label: '赞成' },
    { id: 'b', label: '反对' },
  ],
  scope: 'public',
  status: 'published',
  closes_at: '2026-01-01T00:00:00Z',
})
const result = (id: string, total: number): VoteResult => ({
  vote_id: id,
  counts: { a: total, b: 0 },
  total,
  signature: 'test-only',
  signer_certificate: 'test-only',
  published_at: '2026-01-01T00:00:00Z',
})
const list = () =>
  jsonResponse({ items: [vote('one'), vote('two')], total: 2, page: 1, page_size: 20 })
const render = () => mount(VoteView, { global: { plugins: [pinia] } })

describe('投票结果异步隔离与失败状态', () => {
  beforeEach(() => useSessionStore(pinia).clear())

  it('快速切换议题后丢弃迟到的旧结果', async () => {
    let resolveOld!: (response: Response) => void
    let count = 0
    installApiMock({
      '/api/v1/votes': list,
      '/api/v1/votes/one/results': () =>
        ++count === 1
          ? jsonResponse(result('one', 11))
          : new Promise<Response>((resolve) => {
              resolveOld = resolve
            }),
      '/api/v1/votes/two/results': () => jsonResponse(result('two', 22)),
    })
    const wrapper = render()
    await flushPromises()
    await wrapper.get('.vote-list button').trigger('click')
    await wrapper.findAll('.vote-list button')[1].trigger('click')
    await flushPromises()
    resolveOld(jsonResponse(result('one', 99)))
    await flushPromises()
    expect(wrapper.get('.result').text()).toContain('有效票 22')
    expect(wrapper.get('.result').text()).not.toContain('99')
  })

  it('验签期间切换议题不会把旧议题验签结论贴到新议题', async () => {
    let resolveVerify!: (response: Response) => void
    installApiMock({
      '/api/v1/votes': list,
      '/api/v1/votes/one/results': () => jsonResponse(result('one', 11)),
      '/api/v1/votes/two/results': () => jsonResponse(result('two', 22)),
      '/api/v1/votes/one/results/verify': () =>
        new Promise<Response>((resolve) => {
          resolveVerify = resolve
        }),
    })
    const wrapper = render()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '验证结果签名')!
      .trigger('click')
    await wrapper.findAll('.vote-list button')[1].trigger('click')
    await flushPromises()
    resolveVerify(
      jsonResponse({
        valid: true,
        certificate_valid: true,
        algorithm: 'SM3-with-SM2',
        message: 'test-only',
      }),
    )
    await flushPromises()
    expect(wrapper.find('.verify-state').exists()).toBe(false)
  })

  it('证书无效时使用失败颜色与结论', async () => {
    installApiMock({
      '/api/v1/votes': list,
      '/api/v1/votes/one/results': () => jsonResponse(result('one', 11)),
      '/api/v1/votes/one/results/verify': () =>
        jsonResponse({
          valid: true,
          certificate_valid: false,
          algorithm: 'SM3-with-SM2',
          message: 'test-only',
        }),
    })
    const wrapper = render()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '验证结果签名')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.get('.verify-state').classes()).toContain('invalid')
    expect(wrapper.text()).not.toContain('结果签名与证书均有效')
  })

  it('进行中的投票只允许验签，最终结算前不能导出匿名审计', async () => {
    const ongoing = { ...vote('one'), status: 'open' as const }
    const fetchMock = installApiMock({
      '/api/v1/votes': () => jsonResponse({ items: [ongoing], total: 1, page: 1, page_size: 20 }),
      '/api/v1/votes/one/results': () => jsonResponse(result('one', 1)),
    })
    const wrapper = render()
    await flushPromises()
    const button = wrapper.findAll('button').find((item) => item.text() === '导出匿名审计')!
    expect(button.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('投票截止并完成最终结算后开放')
    await button.trigger('click')
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/votes/one/audit'))).toBe(
      false,
    )
  })

  it('清空投票列表后清除当前议题与结果', async () => {
    let count = 0
    installApiMock({
      '/api/v1/votes': () =>
        ++count === 1 ? list() : jsonResponse({ items: [], total: 0, page: 1, page_size: 20 }),
      '/api/v1/votes/one/results': () => jsonResponse(result('one', 11)),
    })
    const wrapper = render()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '刷新')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('有效票 11')
    expect(wrapper.text()).toContain('暂无可见投票')
  })

  it('阻止超过契约选项上限的创建请求', async () => {
    useSessionStore(pinia).establish('test-token', {
      id: 'test-user',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-01-01T00:00:00Z',
    })
    const mock = installApiMock({
      '/api/v1/votes': () => jsonResponse({ items: [], total: 0, page: 1, page_size: 20 }),
    })
    const wrapper = render()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '发起投票')!
      .trigger('click')
    await flushPromises()
    const dialog = wrapper.findComponent({ name: 'ElDialog' })
    await dialog.get('input').setValue('选项边界')
    await dialog
      .get('textarea')
      .setValue(Array.from({ length: 21 }, (_, i) => `选项 ${i}`).join('\n'))
    await dialog
      .findAll('button')
      .find((b) => b.text() === '创建投票')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('2–20 个选项')
    expect(mock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  })
  it('下载审计时保留发起请求的议题编号', async () => {
    let resolveAudit!: (response: Response) => void
    installApiMock({
      '/api/v1/votes': list,
      '/api/v1/votes/one/results': () => jsonResponse(result('one', 11)),
      '/api/v1/votes/two/results': () => jsonResponse(result('two', 22)),
      '/api/v1/votes/one/audit': () =>
        new Promise<Response>((resolve) => {
          resolveAudit = resolve
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
    let filename = ''
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      filename = this.download
    })
    const wrapper = render()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === '导出匿名审计')!
      .trigger('click')
    await wrapper.findAll('.vote-list button')[1].trigger('click')
    await flushPromises()
    resolveAudit(
      jsonResponse({ vote_id: 'one', ballots: [], total: 0, result_signature: 'test-only' }),
    )
    await flushPromises()
    expect(filename).toBe('vote-one-audit.json')
    expect(create).toHaveBeenCalledOnce()
    expect(revoke).toHaveBeenCalledWith('blob:test')
  })
})
