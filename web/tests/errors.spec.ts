import { describe, expect, it } from 'vitest'

import {
  API_ERROR_MESSAGES,
  HTTP_STATUS_MESSAGES,
  ApiError,
  messageForApiError,
} from '@/api/errors'

describe('API 错误映射', () => {
  it('将稳定错误码映射为中文提示', () => {
    expect(messageForApiError('AUTH_INVALID_CREDENTIALS', 401)).toBe(
      API_ERROR_MESSAGES.AUTH_INVALID_CREDENTIALS,
    )
    expect(messageForApiError('UNSPECIFIED_PROVIDER_ERROR', 503)).toBe(HTTP_STATUS_MESSAGES[503])
  })

  it('未知错误不透传后端信息', () => {
    expect(messageForApiError('UNRECOGNIZED_SERVER_CODE')).toBe(API_ERROR_MESSAGES.UNKNOWN_ERROR)
    expect(messageForApiError({ message: 'sensitive server detail' })).toBe(
      API_ERROR_MESSAGES.UNKNOWN_ERROR,
    )
  })

  it('ApiError 只公开稳定提示和脱敏追踪标识', () => {
    const error = new ApiError({
      code: 'BACKEND_FORBIDDEN_CODE',
      status: 403,
      requestId: 'request-123',
    })

    expect(error.message).toBe(HTTP_STATUS_MESSAGES[403])
    expect(error.status).toBe(403)
    expect(error.requestId).toBe('request-123')
  })
})
