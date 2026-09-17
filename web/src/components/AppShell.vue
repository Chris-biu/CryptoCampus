<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ChatDotRound,
  ChatLineRound,
  Close,
  DocumentChecked,
  Histogram,
  House,
  Lock,
  Menu,
  Promotion,
  Setting,
  SwitchButton,
  User,
  View,
} from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const security = useSecurityStore()
const mobileNavigationOpen = ref(false)
const isSigningOut = ref(false)
const pqcError = ref('')

const navigation = computed(() => [
  { label: '服务大厅', route: { name: 'home' }, icon: House, visible: true },
  { label: '密信快传', route: { name: 'drop-create' }, icon: Promotion, visible: true },
  { label: '匿名树洞', route: { name: 'hole' }, icon: ChatDotRound, visible: true },
  { label: '匿名投票', route: { name: 'vote' }, icon: Histogram, visible: true },
  { label: '文件验真', route: { name: 'verify' }, icon: DocumentChecked, visible: true },
  { label: '安全聊天', route: { name: 'chat' }, icon: ChatLineRound, visible: true },
  { label: '密码透视', route: { name: 'inspect' }, icon: View, visible: true },
  { label: '管理台', route: { name: 'admin' }, icon: Setting, visible: session.isPrivileged },
  {
    label: '性能基准',
    route: { name: 'admin-benchmarks' },
    icon: Histogram,
    visible: session.isPrivileged,
  },
  { label: '用户中心', route: { name: 'me' }, icon: User, visible: true },
])

const activeRouteName = computed(() => {
  const routeName = String(route.name ?? '')
  return routeName.startsWith('inspect-') ? 'inspect' : routeName
})
const displayName = computed(() => session.currentUser?.email ?? '访客')
const sessionLabel = computed(() => (session.isAuthenticated ? '安全会话' : '访客模式'))
const pqcStatusLabel = computed(() => {
  if (security.systemStatus?.providers.pqc === false) return 'PQC 未接入'
  if (security.pqcEnabled === null) return 'PQC 状态未知'
  return security.pqcEnabled ? 'PQC 已开启' : 'PQC 未开启'
})
const tlcpStatusLabel = computed(() => {
  const status = security.systemStatus?.tlcp
  if (status === 'online') return 'TLCP 在线'
  if (status === 'offline') return 'TLCP 离线'
  return 'TLCP 未知'
})

async function changePqcMode(value: string | number | boolean): Promise<void> {
  if (
    typeof value !== 'boolean' ||
    !session.accessToken ||
    security.systemStatus?.providers.pqc !== true
  )
    return
  pqcError.value = ''
  try {
    const enabled = await security.persistPqcMode(value, session.accessToken)
    session.setPqcMode(enabled)
  } catch (error) {
    pqcError.value =
      error instanceof ApiError
        ? messageForApiError(error.code, error.status)
        : messageForApiError('UNKNOWN_ERROR')
  }
}

function closeMobileNavigation(): void {
  mobileNavigationOpen.value = false
}

async function signOut(): Promise<void> {
  if (isSigningOut.value) return
  isSigningOut.value = true
  try {
    await session.signOut()
  } catch {
    // The local session is cleared in the store even when the server session already expired.
  } finally {
    isSigningOut.value = false
    await router.replace({ name: 'login' })
  }
}

onMounted(() => {
  security.setPqcEnabled(session.currentUser?.pqc_mode ?? null)
  void security.loadSystemStatus()
})
</script>

<template>
  <div class="app-shell">
    <button
      class="mobile-menu-button"
      type="button"
      :aria-expanded="mobileNavigationOpen"
      aria-controls="primary-navigation"
      aria-label="打开主导航"
      @click="mobileNavigationOpen = true"
    >
      <el-icon><Menu /></el-icon>
    </button>

    <div
      v-if="mobileNavigationOpen"
      class="navigation-backdrop"
      aria-hidden="true"
      @click="closeMobileNavigation"
    />

    <aside id="primary-navigation" class="app-sidebar" :class="{ 'is-open': mobileNavigationOpen }">
      <div class="brand-row">
        <RouterLink class="brand" :to="{ name: 'home' }" @click="closeMobileNavigation">
          <span class="brand-mark"
            ><el-icon><Lock /></el-icon
          ></span>
          <span><strong>密信校园</strong><small>CryptoCampus</small></span>
        </RouterLink>
        <button
          class="mobile-close-button"
          type="button"
          aria-label="关闭主导航"
          @click="closeMobileNavigation"
        >
          <el-icon><Close /></el-icon>
        </button>
      </div>

      <nav aria-label="主导航">
        <RouterLink
          v-for="item in navigation.filter((entry) => entry.visible)"
          :key="item.label"
          class="navigation-link"
          :class="{ 'is-active': activeRouteName === item.route.name }"
          :to="item.route"
          @click="closeMobileNavigation"
        >
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-security-note">
        <span class="status-dot" :class="{ online: security.engineOnline }" />
        <span>{{ security.statusLabel }}</span>
      </div>
    </aside>

    <section class="app-workspace">
      <header class="app-topbar">
        <div class="account-controls">
          <div class="account-summary">
            <span class="avatar" aria-hidden="true">{{ displayName.charAt(0).toUpperCase() }}</span>
            <span class="account-text">
              <strong>{{ displayName }}</strong>
              <small>{{ sessionLabel }}</small>
            </span>
          </div>
          <button
            class="logout-button"
            data-testid="logout"
            type="button"
            :disabled="isSigningOut"
            @click="signOut"
          >
            <el-icon><SwitchButton /></el-icon>
            <span>{{ isSigningOut ? '退出中' : '退出登录' }}</span>
          </button>
        </div>
        <div class="security-summary" aria-label="全局安全状态">
          <div class="pqc-control">
            <span>
              <strong>抗量子模式</strong>
              <small>{{ pqcStatusLabel }}</small>
            </span>
            <el-switch
              data-testid="pqc-switch"
              :model-value="security.pqcEnabled ?? false"
              :disabled="
                security.pqcEnabled === null ||
                security.isPqcUpdating ||
                security.systemStatus?.providers.pqc !== true
              "
              :loading="security.isPqcUpdating"
              inline-prompt
              active-text="ON"
              inactive-text="OFF"
              aria-label="切换全局抗量子模式"
              @change="changePqcMode"
            />
          </div>
          <el-tag
            :type="security.systemStatus?.tlcp === 'online' ? 'success' : 'info'"
            effect="plain"
            round
          >
            {{ tlcpStatusLabel }}
          </el-tag>
          <span v-if="pqcError" class="pqc-inline-error" role="alert">{{ pqcError }}</span>
        </div>
      </header>

      <main id="main-content" class="app-content" tabindex="-1">
        <RouterView />
      </main>
    </section>
  </div>
</template>
