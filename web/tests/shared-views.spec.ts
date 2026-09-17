import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { createMemoryHistory } from 'vue-router'

import NotFoundView from '@/views/shared/NotFoundView.vue'
import ServicePlaceholderView from '@/views/shared/ServicePlaceholderView.vue'
import StandalonePlaceholderView from '@/views/shared/StandalonePlaceholderView.vue'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'

describe('共享状态页面', () => {
  it('呈现服务占位说明', () => {
    const wrapper = mount(ServicePlaceholderView, {
      props: { title: '安全聊天', description: '核心能力完成后开放。' },
    })
    expect(wrapper.text()).toContain('安全聊天')
    expect(wrapper.text()).toContain('核心能力完成后开放')
  })

  it('呈现独立权限状态说明', () => {
    const wrapper = mount(StandalonePlaceholderView, {
      props: { title: '无权访问', description: '当前账号没有权限。' },
      global: { mocks: { $route: { name: 'forbidden' } } },
    })
    expect(wrapper.text()).toContain('无权访问')
  })

  it('未知路由提供可恢复的返回入口', async () => {
    const router = createAppRouter(createMemoryHistory())
    await router.push('/missing-page')
    await router.isReady()
    const wrapper = mount(NotFoundView, { global: { plugins: [pinia, router] } })
    expect(wrapper.text()).toContain('页面不存在')
    expect(wrapper.get('a').attributes('href')).toBe('/')
  })
})
