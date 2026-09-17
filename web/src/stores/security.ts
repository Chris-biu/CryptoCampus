import { computed, shallowRef } from 'vue'
import { defineStore } from 'pinia'

import { updatePqcMode } from '@/api/me'
import { getSystemStatus } from '@/api/system'
import type { components } from '@/api/schema'

type SystemStatus = components['schemas']['SystemStatus']

export const useSecurityStore = defineStore('security', () => {
  const systemStatus = shallowRef<SystemStatus | null>(null)
  const isLoading = shallowRef(false)
  const isUnavailable = shallowRef(false)
  const pqcEnabled = shallowRef<boolean | null>(null)
  const isPqcUpdating = shallowRef(false)

  const engineOnline = computed(() => systemStatus.value?.engine === 'online')
  const statusLabel = computed(() => {
    if (isLoading.value) return '检测中'
    if (isUnavailable.value) return '状态不可用'
    if (!systemStatus.value) return '状态未知'
    if (systemStatus.value.engine === 'degraded') return '密码引擎降级'
    return engineOnline.value ? '密码引擎在线' : '密码引擎离线'
  })

  function setSystemStatus(status: SystemStatus | null): void {
    systemStatus.value = status
    isUnavailable.value = false
  }

  function setPqcEnabled(enabled: boolean | null): void {
    pqcEnabled.value = enabled
  }

  async function loadSystemStatus(force = false): Promise<void> {
    if (isLoading.value) return
    if (systemStatus.value && !force) return
    isLoading.value = true
    isUnavailable.value = false
    try {
      setSystemStatus(await getSystemStatus())
    } catch {
      systemStatus.value = null
      isUnavailable.value = true
    } finally {
      isLoading.value = false
    }
  }

  async function persistPqcMode(enabled: boolean, accessToken: string): Promise<boolean> {
    if (isPqcUpdating.value) return pqcEnabled.value ?? enabled

    const previousValue = pqcEnabled.value
    pqcEnabled.value = enabled
    isPqcUpdating.value = true
    try {
      const response = await updatePqcMode({ enabled }, accessToken)
      pqcEnabled.value = response.enabled
      return response.enabled
    } catch (error) {
      pqcEnabled.value = previousValue
      throw error
    } finally {
      isPqcUpdating.value = false
    }
  }

  return {
    systemStatus,
    isLoading,
    isUnavailable,
    pqcEnabled,
    isPqcUpdating,
    engineOnline,
    statusLabel,
    loadSystemStatus,
    persistPqcMode,
    setPqcEnabled,
    setSystemStatus,
  }
})
