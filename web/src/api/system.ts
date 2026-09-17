import { apiClient } from './client'
import type { components } from './schema'

export type SystemStatus = components['schemas']['SystemStatus']

export function getSystemStatus(): Promise<SystemStatus> {
  return apiClient.get<SystemStatus>('/system/status')
}
