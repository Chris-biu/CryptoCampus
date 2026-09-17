import { afterEach, describe, expect, it, vi } from 'vitest'

import { apiClient } from '@/api/client'
import { API_ERROR_MESSAGES } from '@/api/errors'

describe('统一 API Client', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('默认解析 JSON 响应并使用同源凭据', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ api: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(apiClient.get<{ api: string }>('/system/status')).resolves.toEqual({ api: 'ok' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/system/status',
      expect.objectContaining({ credentials: 'include' }),
    )
  })

  it('支持 OpenAPI 中的二进制下载响应', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('download-content')))

    const result = await apiClient.get<Blob>('/seals/{seal_id}/sidecar', {
      pathParams: { seal_id: 'example' },
      responseType: 'blob',
    })

    expect(result.size).toBeGreaterThan(0)
  })

  it('错误响应只使用稳定 code，不向用户透传后端 message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: 'AUTH_INVALID_CREDENTIALS',
            message: '不应展示的后端诊断信息',
            request_id: 'request-123',
            details: {},
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    await expect(apiClient.get('/me')).rejects.toMatchObject({
      code: 'AUTH_INVALID_CREDENTIALS',
      message: API_ERROR_MESSAGES.AUTH_INVALID_CREDENTIALS,
      requestId: 'request-123',
    })
  })
})
