import { vi } from 'vitest'

export interface ApiMockRequest {
  init?: RequestInit
  method: string
  url: URL
}

export type ApiMockHandler = (request: ApiMockRequest) => Response | Promise<Response>
export type ApiMockRoute = ApiMockHandler | Response
export type ApiMockRoutes = Readonly<Record<string, ApiMockRoute>>

export function jsonResponse<T>(body: T, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export function createApiFetchMock(routes: ApiMockRoutes) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const rawUrl = input instanceof Request ? input.url : String(input)
    const url = new URL(rawUrl, window.location.origin)
    const route = routes[`${url.pathname}${url.search}`] ?? routes[url.pathname]

    if (!route) {
      throw new Error(`Unexpected API request: ${url.pathname}`)
    }

    if (route instanceof Response) return route

    return route({
      init,
      method: init?.method ?? (input instanceof Request ? input.method : 'GET'),
      url,
    })
  })
}

export function installApiMock(routes: ApiMockRoutes) {
  const fetchMock = createApiFetchMock(routes)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
