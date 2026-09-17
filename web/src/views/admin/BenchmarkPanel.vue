<script setup lang="ts">
/* global crypto, document, URL, Blob, window */
import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { DataAnalysis, Download, VideoPlay } from '@element-plus/icons-vue'
import { getBenchmark, runBenchmark, type BenchmarkResult } from '@/api/benchmarks'
import { ApiError, messageForApiError } from '@/api/errors'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const security = useSecurityStore()
const iterations = ref<number | undefined>(1000)
// Start with the real classical run. PQC comparison is offered only when the
// deployed engine confirms its hybrid-envelope capability.
const includePqc = ref(false)
const pqcBenchmarkReady = computed(() => security.systemStatus?.providers.hybrid_envelope === true)
const loading = ref(false)
const errorMessage = ref('')
const result = shallowRef<BenchmarkResult | null>(null)
const jobId = ref('')
const completed = computed(() => result.value?.status === 'completed')
const pending = computed(
  () => Boolean(jobId.value) && !completed.value && result.value?.status !== 'failed',
)
const maxMean = computed(() =>
  Math.max(1, ...(result.value?.metrics.map((item) => item.mean_ms) ?? [])),
)
let revision = 0
let timer: number | undefined
let releaseDelay: (() => void) | undefined

function cancel(): void {
  revision += 1
  if (timer !== undefined) window.clearTimeout(timer)
  releaseDelay?.()
  timer = undefined
  releaseDelay = undefined
  loading.value = false
}
onBeforeUnmount(cancel)
watch(
  () => session.accessToken,
  () => {
    cancel()
    result.value = null
    jobId.value = ''
  },
)

async function poll(id: string, token: string, run: number): Promise<void> {
  for (let attempt = 0; attempt < 15 && run === revision; attempt += 1) {
    const response = await getBenchmark(id, token)
    if (run !== revision) return
    if (response.id !== id) throw new Error('Benchmark result mismatch')
    result.value = response
    if (response.status === 'completed') return
    if (response.status === 'failed') {
      errorMessage.value = '基准任务执行失败，请检查引擎状态后重试。'
      return
    }
    if (attempt < 14)
      await new Promise<void>((resolve) => {
        releaseDelay = resolve
        timer = window.setTimeout(resolve, 1000)
      })
  }
  if (run === revision) errorMessage.value = '任务仍在运行，请继续查询当前任务。'
}

async function start(resume = false): Promise<void> {
  if (!session.accessToken || !session.isPrivileged || loading.value) return
  if (!resume && pending.value) return
  if (!resume && includePqc.value && !pqcBenchmarkReady.value) {
    errorMessage.value = '当前部署未接入真实 ML-KEM 混合信封，无法运行抗量子开销对比。'
    return
  }
  if (
    !resume &&
    (!Number.isInteger(iterations.value) || iterations.value! < 10 || iterations.value! > 10000)
  ) {
    errorMessage.value = '迭代次数必须是 10–10000 之间的整数。'
    return
  }
  if (resume && !jobId.value) return
  const token = session.accessToken
  const run = ++revision
  loading.value = true
  errorMessage.value = ''
  try {
    if (!resume) {
      result.value = null
      jobId.value = ''
      const job = await runBenchmark(
        { iterations: iterations.value!, include_pqc: includePqc.value },
        token,
        crypto.randomUUID(),
      )
      if (run !== revision) return
      jobId.value = job.id
    }
    await poll(jobId.value, token, run)
  } catch (error) {
    if (run === revision)
      errorMessage.value =
        error instanceof ApiError
          ? messageForApiError(error.code, error.status)
          : messageForApiError('UNKNOWN_ERROR')
  } finally {
    if (run === revision) loading.value = false
  }
}

function exportResult(format: 'csv' | 'json'): void {
  if (!result.value || !completed.value) return
  const content =
    format === 'json'
      ? JSON.stringify(result.value, null, 2)
      : [
          'operation,mean_ms,p99_ms,pqc_overhead_percent',
          ...result.value.metrics.map((m) =>
            [m.operation, m.mean_ms, m.p99_ms, m.pqc_overhead_percent ?? '']
              .map((v) => `"${String(v).replaceAll('"', '""')}"`)
              .join(','),
          ),
        ].join('\n')
  const blob = new Blob([content], {
    type: format === 'json' ? 'application/json' : 'text/csv;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `benchmark-${result.value.id}.${format}`
  anchor.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <section class="benchmark" aria-labelledby="benchmark-title">
    <header>
      <div>
        <p class="eyebrow">真实性能数据</p>
        <h1 id="benchmark-title">业务级密码基准</h1>
        <p>后端执行压测，页面只读取均值、P99 与抗量子开销。</p>
      </div>
      <el-icon><DataAnalysis /></el-icon>
    </header>
    <div class="controls">
      <label
        >迭代次数<el-input-number
          v-model="iterations"
          :min="10"
          :max="10000"
          :step="100"
          :disabled="loading || pending" /></label
      ><label
        >包含抗量子对比<el-switch
          v-model="includePqc"
          :disabled="loading || pending || !pqcBenchmarkReady" /></label
      ><el-button
        type="primary"
        :icon="VideoPlay"
        :loading="loading"
        :disabled="pending || !session.isPrivileged"
        @click="start(false)"
        >开始真实性能测试</el-button
      ><el-button v-if="pending" :loading="loading" @click="start(true)"
        >继续查询当前任务</el-button
      >
    </div>
    <p v-if="!pqcBenchmarkReady" class="capability-note" role="status">
      当前部署仅能测得经典国密性能；ML-KEM 混合信封尚未接入运行时，不能计算真实抗量子开销。
    </p>
    <p v-if="jobId" role="status">任务编号：{{ jobId }} · {{ result?.status ?? '等待查询' }}</p>
    <el-alert
      v-if="errorMessage"
      :title="errorMessage"
      type="warning"
      :closable="false"
      show-icon
    />
    <div v-if="completed" class="metrics">
      <article v-for="metric in result?.metrics" :key="metric.operation">
        <div>
          <strong>{{ metric.operation }}</strong
          ><span
            >均值 {{ metric.mean_ms.toFixed(2) }} ms · P99 {{ metric.p99_ms.toFixed(2) }} ms</span
          >
        </div>
        <el-progress
          :percentage="Math.min(100, (metric.mean_ms / maxMean) * 100)"
          :show-text="false"
        /><small
          >抗量子开销
          {{
            metric.pqc_overhead_percent === null || metric.pqc_overhead_percent === undefined
              ? '无对照样本'
              : `${metric.pqc_overhead_percent.toFixed(1)}%`
          }}</small
        >
      </article>
    </div>
    <div v-else class="empty">
      <strong>{{ loading ? '基准任务运行中' : '尚无本次基准数据' }}</strong
      ><span>N=10–10000；结果由引擎真实执行，不使用前端计时伪造。</span>
    </div>
    <footer>
      <el-button :icon="Download" :disabled="!completed" @click="exportResult('csv')"
        >导出 CSV</el-button
      ><el-button :icon="Download" :disabled="!completed" @click="exportResult('json')"
        >导出 JSON</el-button
      >
    </footer>
  </section>
</template>

<style scoped>
.benchmark {
  display: grid;
  gap: 16px;
  padding: 20px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
header,
.controls,
footer,
article > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
header h1 {
  margin: 4px 0;
  color: var(--cc-primary-dark);
}
header p:not(.eyebrow),
.empty span {
  margin: 0;
  color: var(--cc-muted);
  font-size: 10px;
}
header > .el-icon {
  font-size: 30px;
  color: var(--cc-primary);
}
.controls {
  justify-content: flex-start;
  flex-wrap: wrap;
  padding: 12px;
  background: #f6f8fb;
}
.capability-note {
  margin: 0;
  color: var(--cc-muted);
  font-size: 12px;
  line-height: 1.5;
}
.controls label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  font-weight: 700;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 9px;
}
.metrics article {
  padding: 12px;
  border: 1px solid #e0e6ed;
  border-radius: 9px;
}
.metrics span,
.metrics small {
  color: var(--cc-muted);
  font-size: 9px;
}
.metrics .el-progress {
  margin: 9px 0;
}
.empty {
  display: grid;
  gap: 5px;
  padding: 28px;
  text-align: center;
  background: #f7f9fc;
}
footer {
  justify-content: flex-end;
}
@media (max-width: 760px) {
  .metrics {
    grid-template-columns: 1fr;
  }
  .controls {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
