import { describe, expect, it } from 'vitest'

import { studentUser } from './support/fixtures'
import { mountTestApp } from './support/mount-app'

describe('应用入口', () => {
  it('可以挂载并展示登录注册页面', async () => {
    const { wrapper } = await mountTestApp()

    expect(wrapper.get('h1').text()).toContain('密信校园')
    expect(wrapper.get('[data-testid="login-form"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('都由国密守护')
  })

  it('认证状态存在时挂载应用外壳和主导航', async () => {
    const { wrapper } = await mountTestApp({ route: '/', user: studentUser })

    expect(wrapper.get('nav[aria-label="主导航"]').text()).toContain('密信快传')
    expect(wrapper.get('#main-content').text()).toContain('服务大厅')
    expect(wrapper.text()).not.toContain('管理台')
  })

  it('公开密信提取入口保留可访问的主要内容区域', async () => {
    const { wrapper } = await mountTestApp({ route: '/drop/extract/example-code' })

    expect(wrapper.get('main#main-content').text()).toContain('提取密信')
  })
})
