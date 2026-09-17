import { apiClient } from './client'
import type { components, operations } from './schema'

export type User = components['schemas']['User']
export type KeyringSummary = components['schemas']['KeyringSummary']
export type DeviceSession = components['schemas']['DeviceSession']
export type Quota = components['schemas']['Quota']
export type ChangePasswordRequest =
  operations['changePassword']['requestBody']['content']['application/json']
export type RotateKeyringRequest =
  operations['rotateKeyring']['requestBody']['content']['application/json']
export type SessionListResponse =
  operations['listSessions']['responses'][200]['content']['application/json']
export type QuotaResponse = operations['getQuotas']['responses'][200]['content']['application/json']
export type UpdatePqcModeRequest =
  operations['updatePqcMode']['requestBody']['content']['application/json']
export type UpdatePqcModeResponse =
  operations['updatePqcMode']['responses'][200]['content']['application/json']
export type ExportKeyringBackupRequest =
  operations['exportKeyringBackup']['requestBody']['content']['application/json']
export type DeleteAccountRequest =
  operations['deleteAccount']['requestBody']['content']['application/json']
export type CertificateVerificationResponse =
  operations['verifyOwnCertificate']['responses'][200]['content']['application/json']

export function getMe(accessToken: string): Promise<User> {
  return apiClient.get<User>('/me', { accessToken })
}

export function changePassword(request: ChangePasswordRequest, accessToken: string): Promise<void> {
  return apiClient.patch<void>('/me/password', {
    accessToken,
    body: request,
  })
}

export function getKeyring(accessToken: string): Promise<KeyringSummary> {
  return apiClient.get<KeyringSummary>('/me/keyring', { accessToken })
}

export function verifyOwnCertificate(
  accessToken: string,
): Promise<CertificateVerificationResponse> {
  return apiClient.get<CertificateVerificationResponse>('/me/certificate/verify', { accessToken })
}

export function rotateKeyring(
  request: RotateKeyringRequest,
  idempotencyKey: string,
  accessToken: string,
): Promise<KeyringSummary> {
  return apiClient.post<KeyringSummary>('/me/keyring/rotate', {
    accessToken,
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function listSessions(accessToken: string): Promise<SessionListResponse> {
  return apiClient.get<SessionListResponse>('/me/sessions', { accessToken })
}

export function revokeSession(sessionId: string, accessToken: string): Promise<void> {
  return apiClient.delete<void>('/me/sessions/{session_id}', {
    accessToken,
    pathParams: { session_id: sessionId },
  })
}

export function getQuotas(accessToken: string): Promise<QuotaResponse> {
  return apiClient.get<QuotaResponse>('/me/quotas', { accessToken })
}

export function updatePqcMode(
  request: UpdatePqcModeRequest,
  accessToken: string,
): Promise<UpdatePqcModeResponse> {
  return apiClient.patch<UpdatePqcModeResponse>('/me/pqc-mode', {
    accessToken,
    body: request,
  })
}

export function exportKeyringBackup(
  request: ExportKeyringBackupRequest,
  accessToken: string,
): Promise<Blob> {
  return apiClient.post<Blob>('/me/keyring/export', {
    accessToken,
    body: request,
    responseType: 'blob',
  })
}

export function importKeyringBackup(
  backup: File,
  password: string,
  accessToken: string,
): Promise<KeyringSummary> {
  const form = new FormData()
  form.set('backup', backup)
  form.set('password', password)
  return apiClient.post<KeyringSummary>('/me/keyring/import', {
    accessToken,
    body: form,
  })
}

export function deleteAccount(
  request: DeleteAccountRequest,
  accessToken: string,
): Promise<components['schemas']['Accepted']> {
  return apiClient.delete<components['schemas']['Accepted']>('/me/account', {
    accessToken,
    body: request,
  })
}
