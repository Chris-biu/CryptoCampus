import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'
import { beforeEach, describe, expect, it } from 'vitest'

import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'

describe('基础路由守卫', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    useSessionStore(pinia).clear()
  })

  it('把未登录用户重定向到登录页并保留安全的目标地址', async () => {
    const router = createAppRouter(createMemoryHistory())

    await router.push('/me')

    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.redirect).toBe('/me')
  })

  it('允许游客访问公开的密信提取入口', async () => {
    const router = createAppRouter(createMemoryHistory())

    await router.push('/drop/extract/example-code')

    expect(router.currentRoute.value.name).toBe('drop-extract')
  })

  it.each([
    ['/hole', 'hole'],
    ['/vote', 'vote'],
    ['/verify', 'verify'],
  ])('允许游客访问契约声明的公开页面 %s', async (path, routeName) => {
    const router = createAppRouter(createMemoryHistory())

    await router.push(path)

    expect(router.currentRoute.value.name).toBe(routeName)
  })

  it('阻止学生账号进入管理员页面', async () => {
    useSessionStore(pinia).establish('memory-only-test-value', {
      id: '00000000-0000-4000-8000-000000000001',
      email: 'student@example.edu.cn',
      role: 'student',
      status: 'active',
      pqc_mode: false,
      created_at: '2026-09-02T00:00:00+08:00',
    })
    const router = createAppRouter(createMemoryHistory())

    await router.push('/admin')

    expect(router.currentRoute.value.name).toBe('forbidden')
  })

  it('允许教师账号访问管理员入口', async () => {
    useSessionStore(pinia).establish('memory-only-teacher-token', {
      id: '00000000-0000-4000-8000-000000000041',
      email: 'teacher@example.edu.cn',
      role: 'teacher',
      status: 'active',
      pqc_mode: true,
      created_at: '2026-09-02T00:00:00+08:00',
    })
    const router = createAppRouter(createMemoryHistory())

    await router.push('/admin')

    expect(router.currentRoute.value.name).toBe('admin')
  })
})
