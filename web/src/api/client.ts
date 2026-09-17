import { ApiError, type ApiErrorPayload } from './errors'
import type { paths } from './schema'

const API_BASE_URL = '/api/v1'

export type QueryValue = string | number | boolean | null | undefined
export type ApiResponseType = 'json' | 'blob' | 'text' | 'response'
export type ApiMethod = 'get' | 'post' | 'patch' | 'delete'
export type ApiPathFor<Method extends ApiMethod> = {
  [Path in keyof paths]: paths[Path][Method] extends undefined ? never : Path
}[keyof paths]

export interface ApiRequestOptions extends Omit<RequestInit, 'body'> {
  body?: BodyInit | Record<string, unknown> | null
  pathParams?: Readonly<Record<string, string | number>>
  query?: Readonly<Record<string, QueryValue>>
  accessToken?: string | null
  responseType?: ApiResponseType
}

function createUrl(
  path: string,
  pathParams?: ApiRequestOptions['pathParams'],
  query?: ApiRequestOptions['query'],
): string {
  const renderedPath = path.replaceAll(/\{([^}]+)\}/g, (_, name: string) => {
    const value = pathParams?.[name]
    if (value === undefined) throw new TypeError(`Missing API path parameter: ${name}`)
    return encodeURIComponent(String(value))
  })
  const normalizedPath = renderedPath.startsWith('/') ? renderedPath : `/${renderedPath}`
  const url = new URL(`${API_BASE_URL}${normalizedPath}`, window.location.origin)

  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== null && value !== undefined) url.searchParams.set(key, String(value))
  }

  return `${url.pathname}${url.search}`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isBodyInit(value: unknown): value is BodyInit {
  return (
    typeof value === 'string' ||
    value instanceof Blob ||
    value instanceof FormData ||
    value instanceof URLSearchParams ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value)
  )
}

function normalizeBody(
  body: ApiRequestOptions['body'],
  headers: Headers,
): BodyInit | null | undefined {
  if (body === null || body === undefined || isBodyInit(body)) return body
  headers.set('Content-Type', 'application/json')
  return JSON.stringify(body)
}

async function parseError(response: Response): Promise<ApiError> {
  let payload: ApiErrorPayload = {}

  if (response.headers.get('content-type')?.includes('application/json')) {
    try {
      payload = (await response.json()) as ApiErrorPayload
    } catch {
      payload = {}
    }
  }

  const code = typeof payload.code === 'string' ? payload.code : `HTTP_${response.status}`
  const requestId = typeof payload.request_id === 'string' ? payload.request_id : undefined
  const details = isRecord(payload.details) ? payload.details : undefined
  return new ApiError({ code, status: response.status, requestId, details })
}

async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const {
    accessToken,
    body,
    headers: rawHeaders,
    pathParams,
    query,
    responseType = 'json',
    ...requestInit
  } = options
  const headers = new Headers(rawHeaders)
  if (!headers.has('Accept')) {
    const acceptByType: Record<ApiResponseType, string> = {
      json: 'application/json',
      blob: 'application/octet-stream',
      text: 'text/plain, text/csv',
      response: '*/*',
    }
    headers.set('Accept', acceptByType[responseType])
  }
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`)

  let response: Response
  try {
    response = await fetch(createUrl(path, pathParams, query), {
      ...requestInit,
      body: normalizeBody(body, headers),
      credentials: 'include',
      headers,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError({ code: 'REQUEST_ABORTED', status: 0 })
    }
    throw new ApiError({ code: 'NETWORK_ERROR', status: 0 })
  }

  if (!response.ok) throw await parseError(response)
  if (response.status === 204) return undefined as T
  if (responseType === 'blob') return (await response.blob()) as T
  if (responseType === 'text') return (await response.text()) as T
  if (responseType === 'response') return response as T
  return (await response.json()) as T
}

export const apiClient = Object.freeze({
  get: <T, Path extends ApiPathFor<'get'> = ApiPathFor<'get'>>(
    path: Path,
    options?: ApiRequestOptions,
  ) => apiRequest<T>(path, { ...options, method: 'GET' }),
  post: <T, Path extends ApiPathFor<'post'> = ApiPathFor<'post'>>(
    path: Path,
    options?: ApiRequestOptions,
  ) => apiRequest<T>(path, { ...options, method: 'POST' }),
  patch: <T, Path extends ApiPathFor<'patch'> = ApiPathFor<'patch'>>(
    path: Path,
    options?: ApiRequestOptions,
  ) => apiRequest<T>(path, { ...options, method: 'PATCH' }),
  delete: <T, Path extends ApiPathFor<'delete'> = ApiPathFor<'delete'>>(
    path: Path,
    options?: ApiRequestOptions,
  ) => apiRequest<T>(path, { ...options, method: 'DELETE' }),
})
