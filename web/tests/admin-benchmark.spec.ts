import { describe, expect, it } from 'vitest'
import { getBenchmark, runBenchmark } from '@/api/benchmarks'
import { installApiMock, jsonResponse } from './support/api'

describe('Issue #48 性能基准', () => {
  it('按契约创建真实基准任务', async () => {
    const mock = installApiMock({
      '/api/v1/admin/benchmarks': jsonResponse(
        {
          id: '70000000-0000-4000-8000-000000000001',
          status: 'queued',
          created_at: '2026-09-04T00:00:00Z',
        },
        202,
      ),
    })
    await runBenchmark({ iterations: 1000, include_pqc: true }, 'admin-token', 'benchmark-48')
    const init = mock.mock.calls[0][1] as RequestInit
    expect(JSON.parse(String(init.body))).toEqual({ iterations: 1000, include_pqc: true })
    expect((init.headers as Headers).get('Idempotency-Key')).toBe('benchmark-48')
  })
  it('读取后端计算的均值和 P99', async () => {
    const result = {
      id: '70000000-0000-4000-8000-000000000001',
      status: 'completed',
      metrics: [{ operation: 'SM3(1MB)', mean_ms: 0.52, p99_ms: 0.61, pqc_overhead_percent: null }],
      created_at: '2026-09-04T00:00:00Z',
    }
    installApiMock({
      '/api/v1/admin/benchmarks/70000000-0000-4000-8000-000000000001': jsonResponse(result),
    })
    await expect(getBenchmark(result.id, 'admin-token')).resolves.toEqual(result)
  })
})
