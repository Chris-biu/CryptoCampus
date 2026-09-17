import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App.vue'
import HoleFeedView from '@/views/hole/HoleFeedView.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import { installApiMock, jsonResponse } from './support/api'

function page(items: Array<Record<string, unknown>>, currentPage = 1, total = items.length) {
  return { items, page: currentPage, page_size: 10, total }
}

function post(overrides: Record<string, unknown> = {}) {
  return {
    id: '20000000-0000-4000-8000-000000000001',
    content: '图书馆三楼靠窗的位置很适合复习。',
    credential_prefix: 'A1B2C3D4',
    credential_valid: true,
    status: 'published',
    created_at: '2026-09-04T12:00:00+08:00',
    ...overrides,
  }
}

async function mountPage(routes: Parameters<typeof installApiMock>[0]) {
  const fetchMock = installApiMock(routes)
  const router = createAppRouter(createMemoryHistory())
  await router.push('/hole')
  await router.isReady()
  const wrapper = mount(App, { global: { plugins: [pinia, router] } })
  await flushPromises()
  return { fetchMock, wrapper }
}

describe('Issue #20 匿名树洞热榜', () => {
  beforeEach(() => useSessionStore(pinia).clear())
  afterEach(() => delete window.cryptoCampusCredentialProvider)

  it('游客加载公开热榜且请求不包含认证令牌或发布者身份', async () => {
    const { fetchMock, wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': jsonResponse(
        page([{ ...post(), author_identity: 'must-never-render' }]),
      ),
    })

    expect(wrapper.text()).toContain('图书馆三楼靠窗的位置很适合复习。')
    expect(wrapper.text()).toContain('凭证验签通过')
    expect(wrapper.text()).toContain('A1B2C3D4')
    expect(wrapper.text()).not.toContain('must-never-render')
    const holeCall = fetchMock.mock.calls.find(([url]) =>
      String(url).startsWith('/api/v1/hole/posts'),
    )
    expect(holeCall).toBeDefined()
    const init = holeCall?.[1] as RequestInit
    expect((init.headers as Headers).has('Authorization')).toBe(false)
  })

  it('凭证未通过时隐藏帖子内容并显示失败徽章', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': jsonResponse(
        page([post({ content: 'unverified-content', credential_valid: false })]),
      ),
    })

    expect(wrapper.text()).toContain('凭证验证未通过，内容已停止展示')
    expect(wrapper.text()).toContain('凭证验签未通过')
    expect(wrapper.text()).not.toContain('unverified-content')
  })

  it('不展示已撤下帖子内容', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': jsonResponse(
        page([post({ content: 'withdrawn-content', status: 'withdrawn' })]),
      ),
    })

    expect(wrapper.text()).toContain('暂时没有可公开展示的帖子')
    expect(wrapper.text()).not.toContain('withdrawn-content')
  })

  it('翻页时严格使用契约分页参数', async () => {
    const { fetchMock, wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': jsonResponse(page([post()], 1, 21)),
      '/api/v1/hole/posts?page=2&page_size=10': jsonResponse(
        page([post({ id: '20000000-0000-4000-8000-000000000002', content: '第二页内容' })], 2, 21),
      ),
    })

    const pagination = wrapper.findComponent({ name: 'ElPagination' })
    pagination.vm.$emit('current-change', 2)
    await flushPromises()

    expect(
      fetchMock.mock.calls.some(([url]) => url === '/api/v1/hole/posts?page=2&page_size=10'),
    ).toBe(true)
    expect(wrapper.text()).toContain('第二页内容')
  })

  it('接口失败时显示稳定中文错误且可重试', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': jsonResponse(
        { code: 'INTERNAL_AUTHOR_LOOKUP', message: 'raw identity diagnostic' },
        503,
      ),
    })

    expect(wrapper.text()).toContain('密码服务暂时不可用')
    expect(wrapper.text()).toContain('重新加载')
    expect(wrapper.text()).not.toContain('raw identity diagnostic')
    expect(wrapper.text()).not.toContain('INTERNAL_AUTHOR_LOOKUP')
  })

  it('安全凭证组件就绪后完成匿名发布、评论与点赞', async () => {
    useSessionStore(pinia).establish('memory-token', {
      id: 'user-1',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-09-10T00:00:00Z',
    })
    window.cryptoCampusCredentialProvider = {
      blind: vi.fn().mockResolvedValue({ blindedMessage: 'blinded', state: 'opaque' }),
      unblind: vi.fn().mockImplementation(({ service, period }) =>
        Promise.resolve({
          sn: `sn-${service}`,
          service,
          period,
          signature: 'signature',
        }),
      ),
    }
    const { fetchMock, wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': () => jsonResponse(page([post()])),
      '/api/v1/hole/credentials/commitments': () =>
        jsonResponse(
          {
            commitment_id: '0123456789abcdef0123456789abcdef',
            commitment_point: '04' + '22'.repeat(64),
            expires_at: '2026-09-10T12:10:00Z',
            algorithm: 'SM2-BLIND-PROTOCOL-V1',
          },
          201,
        ),
      '/api/v1/hole/credentials': () =>
        jsonResponse(
          { blind_signature: 'blind-signature', algorithm: 'SM2-BLIND-PROTOCOL-V1' },
          201,
        ),
      '/api/v1/hole/posts': ({ method }) =>
        method === 'POST' ? jsonResponse(post(), 201) : jsonResponse(page([post()])),
      [`/api/v1/hole/posts/${post().id}/comments?page=1&page_size=20`]: () =>
        jsonResponse({
          items: [
            {
              id: 'comment-1',
              post_id: post().id,
              content: '匿名评论内容',
              credential_prefix: 'C0FFEE',
              credential_valid: true,
              created_at: '2026-09-10T00:00:00Z',
            },
          ],
          page: 1,
          page_size: 20,
          total: 1,
        }),
      [`/api/v1/hole/posts/${post().id}/comments`]: jsonResponse({ id: 'comment-1' }, 201),
      [`/api/v1/hole/posts/${post().id}/likes`]: jsonResponse({ accepted: true }, 201),
    })

    await wrapper.get('.post-actions button').trigger('click')
    await flushPromises()
    const pageState = wrapper.findComponent(HoleFeedView).vm as unknown as {
      commentContent: string
      publishComment: () => Promise<void>
    }
    pageState.commentContent = '新的匿名评论'
    await pageState.publishComment()
    await wrapper
      .findAll('button')
      .find((item) => item.text().includes('匿名点赞'))!
      .trigger('click')
    await flushPromises()

    const pageView = wrapper.findComponent(HoleFeedView)
    const state = pageView.vm as unknown as {
      composerContent: string
      errorMessage: string
      publishPost: () => Promise<void>
    }
    state.composerContent = '新的匿名帖子'
    await state.publishPost()
    expect(state.errorMessage).toBe('')
    await vi.waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([url, init]) => String(url) === '/api/v1/hole/posts' && init?.method === 'POST',
        ),
      ).toBe(true)
    })

    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(
      expect.arrayContaining([
        '/api/v1/hole/credentials/commitments',
        '/api/v1/hole/credentials',
        '/api/v1/hole/posts',
        `/api/v1/hole/posts/${post().id}/comments?page=1&page_size=20`,
        `/api/v1/hole/posts/${post().id}/comments`,
        `/api/v1/hole/posts/${post().id}/likes`,
      ]),
    )
    expect(wrapper.text()).toContain('帖子已匿名发布')
  })

  it('在开发环境下支持切换 Dev 凭证适配器挂载状态', async () => {
    const { wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': () => jsonResponse(page([post()])),
    })
    const holeView = wrapper.findComponent(HoleFeedView)
    const vm = holeView.vm as unknown as {
      toggleDevProvider: () => void
      credentialProviderReady: boolean
    }
    expect(vm.credentialProviderReady).toBe(false)
    vm.toggleDevProvider()
    expect(vm.credentialProviderReady).toBe(true)
    vm.toggleDevProvider()
    expect(vm.credentialProviderReady).toBe(false)
  })

  it('匿名发布失败时在仍打开的发布对话框内显示错误', async () => {
    useSessionStore(pinia).establish('memory-token', {
      id: 'user-1',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-09-10T00:00:00Z',
    })
    window.cryptoCampusCredentialProvider = {
      blind: vi.fn().mockRejectedValue(new Error('invalid signer key')),
      unblind: vi.fn(),
    }
    const { wrapper } = await mountPage({
      '/api/v1/hole/posts?page=1&page_size=10': () => jsonResponse(page([post()])),
      '/api/v1/hole/credentials/commitments': () =>
        jsonResponse(
          {
            commitment_id: '0123456789abcdef0123456789abcdef',
            commitment_point: '04' + '22'.repeat(64),
            expires_at: '2026-09-10T12:10:00Z',
            algorithm: 'SM2-BLIND-PROTOCOL-V1',
          },
          201,
        ),
    })
    const pageView = wrapper.findComponent(HoleFeedView)
    const state = pageView.vm as unknown as {
      composerOpen: boolean
      composerContent: string
      composerError: string
      publishPost: () => Promise<void>
    }
    state.composerOpen = true
    state.composerContent = '应显示失败提示的帖子'

    await state.publishPost()
    await flushPromises()

    expect(state.composerOpen).toBe(true)
    expect(state.composerError).toBe('操作未完成，请稍后再试。')
    expect(wrapper.find('.dialog-error').text()).toContain('操作未完成，请稍后再试。')
  })
})
