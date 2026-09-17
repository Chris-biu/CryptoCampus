import { apiClient } from './client'
import type { components, operations } from './schema'

export type AuthSession = components['schemas']['AuthSession']
export type LoginRequest = components['schemas']['LoginRequest']
export type RegisterRequest = components['schemas']['RegisterRequest']
export type RequestRegistrationCode =
  operations['requestRegistrationCode']['requestBody']['content']['application/json']
export type RegistrationCodeAccepted =
  operations['requestRegistrationCode']['responses'][202]['content']['application/json']

export function requestRegistrationCode(
  request: RequestRegistrationCode,
): Promise<RegistrationCodeAccepted> {
  return apiClient.post<RegistrationCodeAccepted>('/auth/register/request-code', {
    body: { ...request },
  })
}

export function register(request: RegisterRequest): Promise<AuthSession> {
  return apiClient.post<AuthSession>('/auth/register', { body: { ...request } })
}

export function login(request: LoginRequest): Promise<AuthSession> {
  return apiClient.post<AuthSession>('/auth/login', { body: { ...request } })
}

export function refreshSession(): Promise<AuthSession> {
  return apiClient.post<AuthSession>('/auth/refresh')
}

export function logout(): Promise<void> {
  return apiClient.post<void>('/auth/logout')
}
