import { apiClient } from './client'
import type { components, operations } from './schema'

export type Job = components['schemas']['Job']
export type BenchmarkResult = components['schemas']['BenchmarkResult']
export type RunBenchmarkRequest =
  operations['runBenchmark']['requestBody']['content']['application/json']

export function runBenchmark(
  request: RunBenchmarkRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<Job> {
  return apiClient.post<Job>('/admin/benchmarks', {
    accessToken,
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function getBenchmark(id: string, accessToken: string): Promise<BenchmarkResult> {
  return apiClient.get<BenchmarkResult>('/admin/benchmarks/{benchmark_id}', {
    accessToken,
    pathParams: { benchmark_id: id },
  })
}
