import { apiClient } from './client'
import type { components, operations } from './schema'

export type SystemStatus = components['schemas']['SystemStatus']
export type User = components['schemas']['User']
export type UserPage = components['schemas']['UserPage']
export type QuotaPage = components['schemas']['QuotaPage']
export type RevocationEntry = components['schemas']['RevocationEntry']
export type UpdateUserStatusRequest =
  operations['updateUserStatus']['requestBody']['content']['application/json']
export type UpdateUserRoleRequest =
  operations['updateUserRole']['requestBody']['content']['application/json']

export function getEngineDetails(accessToken: string): Promise<SystemStatus> {
  return apiClient.get<SystemStatus>('/admin/engine', { accessToken })
}

export function reloadPqcProvider(
  accessToken: string,
  idempotencyKey: string,
): Promise<SystemStatus> {
  return apiClient.post<SystemStatus>('/admin/providers/reload', {
    accessToken,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function listAdminUsers(accessToken: string, page = 1, pageSize = 20): Promise<UserPage> {
  return apiClient.get<UserPage>('/admin/users', {
    accessToken,
    query: { page, page_size: pageSize },
  })
}

export function updateUserStatus(
  userId: string,
  request: UpdateUserStatusRequest,
  accessToken: string,
): Promise<User> {
  return apiClient.patch<User>('/admin/users/{user_id}/status', {
    accessToken,
    pathParams: { user_id: userId },
    body: request,
  })
}

export function updateUserRole(
  userId: string,
  request: UpdateUserRoleRequest,
  accessToken: string,
): Promise<User> {
  return apiClient.patch<User>('/admin/users/{user_id}/role', {
    accessToken,
    pathParams: { user_id: userId },
    body: request,
  })
}

export function resetUserQuotas(
  userId: string,
  accessToken: string,
  idempotencyKey: string,
): Promise<QuotaPage> {
  return apiClient.post<QuotaPage>('/admin/users/{user_id}/quotas/reset', {
    accessToken,
    pathParams: { user_id: userId },
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function withdrawHolePost(
  postId: string,
  reason: string,
  accessToken: string,
): Promise<RevocationEntry> {
  return apiClient.patch<RevocationEntry>('/admin/hole/posts/{post_id}/withdraw', {
    accessToken,
    pathParams: { post_id: postId },
    body: { reason },
  })
}

export function destroyDrop(code: string, accessToken: string): Promise<void> {
  return apiClient.delete<void>('/admin/drops/{code}/destroy', {
    accessToken,
    pathParams: { code },
  })
}

export function flagVoteForAudit(
  voteId: string,
  reason: string,
  accessToken: string,
): Promise<components['schemas']['Accepted']> {
  return apiClient.post<components['schemas']['Accepted']>('/admin/votes/{vote_id}/audit-flags', {
    accessToken,
    pathParams: { vote_id: voteId },
    body: { reason },
  })
}

export function exportAdminAudit(
  format: 'csv' | 'json',
  accessToken: string,
): Promise<Blob> {
  return apiClient.get<Blob>('/admin/audit/export', {
    accessToken,
    query: { format },
    responseType: 'blob',
  })
}
