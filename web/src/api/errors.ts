export interface ApiErrorPayload {
  code?: unknown
  message?: unknown
  request_id?: unknown
  details?: unknown
}

export const API_ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  AUTH_INVALID_CREDENTIALS: '校园邮箱或口令不正确。',
  NOT_IMPLEMENTED: '此功能暂未开放。',
  NETWORK_ERROR: '网络连接失败，请检查网络后重试。',
  REQUEST_ABORTED: '请求已取消。',
  CRYPTO_CLIENT_UNAVAILABLE: '安全凭证组件尚未接入，请等待密码引擎提供客户端适配器。',
  CRYPTO_CLIENT_INVALID: '安全凭证组件返回了无效结果，操作已停止。',
  UNKNOWN_ERROR: '操作未完成，请稍后再试。',
})

export const HTTP_STATUS_MESSAGES: Readonly<Record<number, string>> = Object.freeze({
  400: '请求无法处理，请检查输入内容。',
  401: '登录状态已失效，请重新登录。',
  403: '你没有执行此操作的权限。',
  404: '未找到请求的内容，或内容已失效。',
  409: '当前状态已发生变化，请刷新后重试。',
  413: '文件超过当前操作允许的大小。',
  422: '提交内容不符合要求，请检查后重试。',
  429: '操作过于频繁或额度已用完，请稍后再试。',
  500: '服务暂时异常，请稍后再试。',
  501: '此功能暂未开放。',
  503: '密码服务暂时不可用，请稍后再试。',
})

export function messageForApiError(code: unknown, status = 0): string {
  if (typeof code === 'string' && API_ERROR_MESSAGES[code]) return API_ERROR_MESSAGES[code]
  return HTTP_STATUS_MESSAGES[status] ?? API_ERROR_MESSAGES.UNKNOWN_ERROR
}

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly requestId?: string
  readonly details?: Readonly<Record<string, unknown>>

  constructor(options: {
    code: string
    status: number
    requestId?: string
    details?: Readonly<Record<string, unknown>>
  }) {
    super(messageForApiError(options.code, options.status))
    this.name = 'ApiError'
    this.code = options.code
    this.status = options.status
    this.requestId = options.requestId
    this.details = options.details
  }
}
