import { apiClient } from './client'
import type { components, operations } from './schema'

export type DropMetadata = components['schemas']['DropMetadata']
export type ExtractedDrop = components['schemas']['ExtractedDrop']
export type ExtractDropRequest =
  operations['extractDrop']['requestBody']['content']['application/json']
export type TtlPolicy = components['schemas']['TtlPolicy']
export type CreateDropResponse = components['schemas']['CreateDropResponse']
export type CreateTextDropRequest =
  operations['createTextDrop']['requestBody']['content']['application/json']

export interface CreateFileDropRequest {
  file: File
  ttl_policy: TtlPolicy
  pqc_mode: boolean
  access_password?: string
}

function requestHeaders(idempotencyKey: string): HeadersInit {
  return { 'Idempotency-Key': idempotencyKey }
}

export function getDropMetadata(code: string): Promise<DropMetadata> {
  return apiClient.get<DropMetadata>('/drops/{code}', { pathParams: { code } })
}

export async function extractDrop(
  code: string,
  request: ExtractDropRequest,
  idempotencyKey: string,
): Promise<ExtractedDrop> {
  const response = await apiClient.post<Response>('/drops/{code}/extract', {
    pathParams: { code },
    body: request,
    headers: {
      ...requestHeaders(idempotencyKey),
      Accept: 'application/octet-stream, application/json;q=0.9, */*;q=0.8',
    },
    responseType: 'response',
  })

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/octet-stream')) {
    const blob = await response.blob()
    const downloadUrl = URL.createObjectURL(blob)
    const sigValid = response.headers.get('x-signature-valid') === 'true'
    const certValid = response.headers.get('x-certificate-valid') === 'true'
    const inspectId = response.headers.get('x-inspect-record-id') || ''
    const contentDisposition = response.headers.get('content-disposition') || ''
    const match = /filename="?([^";]+)"?/.exec(contentDisposition)
    const filename = match ? match[1] : undefined

    return {
      kind: 'file',
      download_url: downloadUrl,
      signature_valid: sigValid,
      certificate_valid: certValid,
      inspect_record_id: inspectId,
      filename,
    }
  }

  return (await response.json()) as ExtractedDrop
}

export function createTextDrop(
  request: CreateTextDropRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<CreateDropResponse> {
  return apiClient.post<CreateDropResponse>('/drops/text', {
    accessToken,
    body: request,
    headers: requestHeaders(idempotencyKey),
  })
}

export function createFileDrop(
  request: CreateFileDropRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<CreateDropResponse> {
  const body = new FormData()
  body.set('file', request.file)
  body.set('ttl_policy', request.ttl_policy)
  body.set('pqc_mode', String(request.pqc_mode))
  if (request.access_password) body.set('access_password', request.access_password)

  return apiClient.post<CreateDropResponse>('/drops/file', {
    accessToken,
    body,
    headers: requestHeaders(idempotencyKey),
  })
}
