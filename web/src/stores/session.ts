import { computed, ref, shallowRef } from 'vue'
import { defineStore } from 'pinia'

import {
  login,
  logout,
  refreshSession,
  register,
  type LoginRequest,
  type RegisterRequest,
} from '@/api/auth'
import type { components } from '@/api/schema'

type User = components['schemas']['User']

export const useSessionStore = defineStore('session', () => {
  // Access token intentionally remains in memory. Refresh credentials are httpOnly cookies.
  const accessToken = shallowRef<string | null>(null)
  const currentUser = shallowRef<User | null>(null)
  const isInitialized = ref(false)
  const isRestoring = ref(false)
  let restorePromise: Promise<void> | null = null
  const isAuthenticated = computed(() => accessToken.value !== null)
  const isPrivileged = computed(
    () => currentUser.value?.role === 'admin' || currentUser.value?.role === 'teacher',
  )

  function establish(token: string, user: User): void {
    accessToken.value = token
    currentUser.value = user
    isInitialized.value = true
  }

  function clear(): void {
    accessToken.value = null
    currentUser.value = null
    isInitialized.value = true
  }

  function establishFromSession(session: components['schemas']['AuthSession']): void {
    establish(session.access_token, session.user)
  }

  function setPqcMode(enabled: boolean): void {
    if (!currentUser.value) return
    currentUser.value = { ...currentUser.value, pqc_mode: enabled }
  }

  async function signIn(request: LoginRequest): Promise<void> {
    establishFromSession(await login(request))
  }

  async function signUp(request: RegisterRequest): Promise<void> {
    establishFromSession(await register(request))
  }

  async function restore(): Promise<void> {
    if (isInitialized.value) return
    if (restorePromise) return restorePromise

    restorePromise = (async () => {
      isRestoring.value = true
      try {
        establishFromSession(await refreshSession())
      } catch {
        clear()
      } finally {
        isRestoring.value = false
        restorePromise = null
      }
    })()

    return restorePromise
  }

  async function signOut(): Promise<void> {
    try {
      await logout()
    } finally {
      clear()
    }
  }

  return {
    accessToken,
    currentUser,
    isAuthenticated,
    isInitialized,
    isPrivileged,
    isRestoring,
    establish,
    clear,
    restore,
    setPqcMode,
    signIn,
    signOut,
    signUp,
  }
})
