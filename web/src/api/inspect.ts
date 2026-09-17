import { apiClient } from './client'
import type { components } from './schema'

export type InspectRecord = components['schemas']['InspectRecord']
export type InspectRecordPage = components['schemas']['InspectRecordPage']
export type InspectMetadataPage = components['schemas']['InspectMetadataPage']
export type TlcpHandshake = components['schemas']['TlcpHandshake']
export type ExperimentRequest = components['schemas']['ExperimentRequest']
export type ExperimentResult = components['schemas']['ExperimentResult']

export function listInspectRecords(
  accessToken: string,
  page = 1,
  pageSize = 20,
): Promise<InspectRecordPage> {
  return apiClient.get<InspectRecordPage>('/inspect/records', {
    accessToken,
    query: { page, page_size: pageSize },
  })
}

export function getInspectRecord(recordId: string, accessToken: string): Promise<InspectRecord> {
  return apiClient.get<InspectRecord>('/inspect/records/{record_id}', {
    accessToken,
    pathParams: { record_id: recordId },
  })
}

export function exportInspectReport(recordId: string, accessToken: string): Promise<string> {
  return apiClient.get<string>('/inspect/records/{record_id}/report', {
    accessToken,
    pathParams: { record_id: recordId },
    responseType: 'text',
  })
}

export function listInspectRecordMetadata(
  accessToken: string,
  page = 1,
  pageSize = 10,
): Promise<InspectMetadataPage> {
  return apiClient.get<InspectMetadataPage>('/admin/inspect-records', {
    accessToken,
    query: { page, page_size: pageSize },
  })
}

export function getTlcpHandshake(accessToken: string): Promise<TlcpHandshake> {
  return apiClient.get<TlcpHandshake>('/inspect/tlcp/handshake', { accessToken })
}

export function runCryptoExperiment(
  request: ExperimentRequest,
  accessToken: string,
): Promise<ExperimentResult> {
  return apiClient.post<ExperimentResult>('/inspect/experiments', {
    accessToken,
    body: request,
  })
}
