import { apiClient } from './client'
import type { components } from './schema'

export type Seal = components['schemas']['Seal']
export type VerificationResult = components['schemas']['VerificationResult']

export interface CreateSealRequest {
  file: File
  sealProfile: 'personal' | 'department' | 'academic'
  pqcMode: boolean
  outputFormat: 'sidecar' | 'qr' | 'pdf_signature_page'
}

export function createSeal(
  request: CreateSealRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<Seal> {
  const body = new FormData()
  body.set('file', request.file)
  body.set('seal_profile', request.sealProfile)
  body.set('pqc_mode', String(request.pqcMode))
  body.set('output_format', request.outputFormat)
  return apiClient.post<Seal>('/seals', {
    accessToken,
    body,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function verifyFile(file: File, seal: File): Promise<VerificationResult> {
  const body = new FormData()
  body.set('file', file)
  body.set('seal', seal)
  return apiClient.post<VerificationResult>('/verifications', { body })
}

export function downloadSealSidecar(sealId: string): Promise<Blob> {
  return apiClient.get<Blob>('/seals/{seal_id}/sidecar', {
    pathParams: { seal_id: sealId },
    responseType: 'blob',
  })
}
