import {
  createRouter,
  createWebHistory,
  type RouteLocationNormalized,
  type RouteRecordRaw,
  type Router,
  type RouterHistory,
} from 'vue-router'

import BenchmarkPanel from '@/views/admin/BenchmarkPanel.vue'
import AppShell from '@/components/AppShell.vue'
import AdminEngineView from '@/views/admin/AdminEngineView.vue'
import { pinia } from '@/stores'
import { useSessionStore } from '@/stores/session'
import LoginView from '@/views/auth/LoginView.vue'
import DropExtractView from '@/views/drop/DropExtractView.vue'
import DropCreateView from '@/views/drop/DropCreateView.vue'
import HomeView from '@/views/home/HomeView.vue'
import HoleFeedView from '@/views/hole/HoleFeedView.vue'
import InspectView from '@/views/inspect/InspectView.vue'
import TlcpTimelineView from '@/views/inspect/TlcpTimelineView.vue'
import AlgorithmLabView from '@/views/inspect/AlgorithmLabView.vue'
import MeView from '@/views/me/MeView.vue'
import NotFoundView from '@/views/shared/NotFoundView.vue'
import ServicePlaceholderView from '@/views/shared/ServicePlaceholderView.vue'
import StandalonePlaceholderView from '@/views/shared/StandalonePlaceholderView.vue'
import VoteView from '@/views/vote/VoteView.vue'
import VerifyView from '@/views/verify/VerifyView.vue'

declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean
    roles?: ReadonlyArray<'student' | 'admin' | 'teacher' | 'system'>
    title?: string
  }
}

export const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginView,
    meta: { title: '登录' },
  },
  {
    path: '/drop/extract/:code',
    alias: '/d/:code',
    name: 'drop-extract',
    component: DropExtractView,
    meta: { title: '提取密信' },
  },
  {
    path: '/',
    component: AppShell,
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'home',
        component: HomeView,
        meta: { title: '服务大厅' },
      },
      {
        path: 'drop/create',
        name: 'drop-create',
        component: DropCreateView,
        meta: { title: '密信快传 · 创建' },
      },
      {
        path: 'hole',
        name: 'hole',
        component: HoleFeedView,
        meta: { title: '匿名树洞', requiresAuth: false },
      },
      {
        path: 'vote',
        name: 'vote',
        component: VoteView,
        meta: { title: '匿名投票', requiresAuth: false },
      },
      {
        path: 'verify',
        name: 'verify',
        component: VerifyView,
        meta: { title: '文件验真', requiresAuth: false },
      },
      {
        path: 'chat',
        name: 'chat',
        component: ServicePlaceholderView,
        props: { title: '安全聊天', description: '安全聊天属于进阶功能，将在核心流程完成后实现。' },
        meta: { title: '安全聊天' },
      },
      {
        path: 'inspect',
        name: 'inspect',
        component: InspectView,
        meta: { title: '密码透视' },
      },
      {
        path: 'inspect/records/:recordId',
        name: 'inspect-record',
        component: InspectView,
        meta: { title: '密码透视记录' },
      },
      {
        path: 'inspect/tlcp',
        name: 'inspect-tlcp',
        component: TlcpTimelineView,
        meta: { title: '密码透视 · TLCP 时序' },
      },
      {
        path: 'inspect/experiments',
        name: 'inspect-experiments',
        component: AlgorithmLabView,
        meta: { title: '密码透视 · 算法试验台' },
      },
      {
        path: 'admin/benchmarks',
        name: 'admin-benchmarks',
        component: BenchmarkPanel,
        meta: { title: '性能基准', roles: ['admin', 'teacher'] },
      },
      {
        path: 'admin',
        name: 'admin',
        component: AdminEngineView,
        meta: { title: '管理台', roles: ['admin', 'teacher'] },
      },
      {
        path: 'me',
        name: 'me',
        component: MeView,
        meta: { title: '用户中心' },
      },
    ],
  },
  {
    path: '/forbidden',
    name: 'forbidden',
    component: StandalonePlaceholderView,
    props: { title: '无权访问', description: '当前账号没有访问此页面的权限。' },
    meta: { title: '无权访问', requiresAuth: true },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: NotFoundView,
    meta: { title: '页面不存在' },
  },
]

function safeRedirectTarget(route: RouteLocationNormalized): string {
  return route.fullPath.startsWith('/') && !route.fullPath.startsWith('//') ? route.fullPath : '/'
}

export function installRouteGuards(targetRouter: Router): void {
  targetRouter.beforeEach(async (to) => {
    const session = useSessionStore(pinia)

    // This client-side guard is for navigation UX only. Every API enforces authorization again.

    await session.restore()

    if (to.meta.requiresAuth && !session.isAuthenticated) {
      return { name: 'login', query: { redirect: safeRedirectTarget(to) } }
    }

    if (to.name === 'login' && session.isAuthenticated) return { name: 'home' }

    if (to.meta.roles?.length) {
      const role = session.currentUser?.role
      if (!role || !to.meta.roles.includes(role)) return { name: 'forbidden' }
    }

    document.title = to.meta.title ? `${to.meta.title} · 密信校园` : '密信校园 CryptoCampus'
    return true
  })
}

export function createAppRouter(history: RouterHistory = createWebHistory()): Router {
  const targetRouter = createRouter({ history, routes })
  installRouteGuards(targetRouter)
  return targetRouter
}

export const router = createAppRouter()
