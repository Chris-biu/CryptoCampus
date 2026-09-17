import { mount } from '@vue/test-utils'
import { setActivePinia } from 'pinia'
import { createMemoryHistory } from 'vue-router'

import App from '@/App.vue'
import type { components } from '@/api/schema'
import { createAppRouter } from '@/router'
import { pinia } from '@/stores'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

interface MountTestAppOptions {
  route?: string
  user?: components['schemas']['User']
}

export async function mountTestApp({ route = '/login', user }: MountTestAppOptions = {}) {
  setActivePinia(pinia)

  const session = useSessionStore(pinia)
  session.clear()
  if (user) session.establish('test-token-redacted', user)

  const security = useSecurityStore(pinia)
  security.setSystemStatus(null)
  security.setPqcEnabled(user?.pqc_mode ?? null)

  const router = createAppRouter(createMemoryHistory())
  await router.push(route)
  await router.isReady()

  const wrapper = mount(App, {
    global: { plugins: [pinia, router] },
  })

  return { pinia, router, security, session, wrapper }
}
