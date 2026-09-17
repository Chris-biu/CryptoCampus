<script setup lang="ts">
import { computed, ref, shallowRef } from 'vue'
import { ArrowLeft, Download, RefreshLeft, VideoPlay } from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import { runCryptoExperiment, type ExperimentRequest, type ExperimentResult } from '@/api/inspect'
import { useSessionStore } from '@/stores/session'

type SupportedExperiment = Extract<
  ExperimentRequest['experiment'],
  'sm4_mode_compare' | 'sm3_avalanche'
>

const MAX_INPUT_LENGTH = 1_048_576
const session = useSessionStore()
const experiment = ref<SupportedExperiment>('sm4_mode_compare')
const input = ref('国密课堂演示：重复结构能够帮助观察不同工作模式的输出特征。')
const result = shallowRef<ExperimentResult | null>(null)
const isRunning = ref(false)
const isExporting = ref(false)
const errorMessage = ref('')

const examples: Readonly<Record<SupportedExperiment, string>> = Object.freeze({
  sm4_mode_compare: 'CAMPUS-2026 | CAMPUS-2026 | CAMPUS-2026 | CAMPUS-2026',
  sm3_avalanche: '密码软件综合实践 / avalanche-demo / bit-0',
})

const experimentMeta = Object.freeze({
  sm4_mode_compare: {
    eyebrow: 'SM4 · 模式对照',
    title: '相同结构，不同泄露面',
    description: '把教学输入交给后端密码引擎，对照不同工作模式返回的脱敏结果。',
  },
  sm3_avalanche: {
    eyebrow: 'SM3 · 雪崩效应',
    title: '只改一位，观察摘要扩散',
    description: '由后端翻转教学输入中的一位并统计摘要差异；浏览器不计算 SM3。',
  },
}) satisfies Readonly<
  Record<SupportedExperiment, Record<'eyebrow' | 'title' | 'description', string>>
>

const blockedKey =
  /(password|passphrase|plaintext|plain_text|private|secret|session[_-]?key|refresh[_-]?token|access[_-]?token|kek|credential|business[_-]?plaintext|full[_-]?intermediate)/i

const activeMeta = computed(() => experimentMeta[experiment.value])
const inputLength = computed(() => input.value.length)
const inputTooLong = computed(() => inputLength.value > MAX_INPUT_LENGTH)
const safeSteps = computed(() =>
  (result.value?.steps ?? []).slice(0, 20).map((step) => safeText(step, 220)),
)
const safeValues = computed(() => safeRedactedEntries(result.value?.redacted_values))
const avalancheMetric = computed(() => {
  if (experiment.value !== 'sm3_avalanche' || !result.value) return null
  const values = result.value.redacted_values
  const changed = numericValue(values, ['changed_bits', 'flipped_bits', 'different_bits'])
  const total = numericValue(values, ['total_bits', 'digest_bits']) ?? 256
  if (changed === null || total <= 0) return null
  return {
    changed,
    total,
    percent: Math.min(100, Math.max(0, (changed / total) * 100)),
  }
})

function safeText(value: unknown, maxLength = 160): string {
  const normalized = typeof value === 'string' ? value.trim() : String(value)
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized
}

function numericValue(values: Record<string, unknown>, keys: readonly string[]): number | null {
  for (const key of keys) {
    const value = values[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
  }
  return null
}

function formatRedactedValue(value: unknown): string {
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '不可用'
  if (typeof value === 'boolean') return value ? '是' : '否'
  if (typeof value === 'string') return safeText(value)
  if (Array.isArray(value))
    return value
      .slice(0, 8)
      .map((item) => safeText(item, 40))
      .join(' · ')
  if (value && typeof value === 'object') return '已脱敏结构'
  return '未提供'
}

function safeRedactedEntries(
  values: Record<string, unknown> | undefined,
): ReadonlyArray<[string, string]> {
  return Object.entries(values ?? {})
    .filter(([key]) => !blockedKey.test(key))
    .slice(0, 16)
    .map(([key, value]) => [key.replaceAll('_', ' '), formatRedactedValue(value)])
}

function failureMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 400) return '教学输入或试验参数不符合接口约束。'
  if (error instanceof ApiError && error.status === 503) return '密码引擎暂不可用，请稍后重试。'
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function chooseExperiment(next: SupportedExperiment): void {
  if (experiment.value === next) return
  experiment.value = next
  input.value = examples[next]
  result.value = null
  errorMessage.value = ''
}

function useExample(): void {
  input.value = examples[experiment.value]
  result.value = null
  errorMessage.value = ''
}

function reset(): void {
  input.value = ''
  result.value = null
  errorMessage.value = ''
}

async function runExperiment(): Promise<void> {
  if (!session.accessToken || isRunning.value || inputTooLong.value) return
  isRunning.value = true
  result.value = null
  errorMessage.value = ''
  try {
    result.value = await runCryptoExperiment(
      { experiment: experiment.value, input: input.value },
      session.accessToken,
    )
  } catch (error) {
    errorMessage.value = failureMessage(error)
  } finally {
    isRunning.value = false
  }
}

function reportLines(): string[] {
  if (!result.value) return []
  return [
    '# CryptoCampus 脱敏算法试验报告',
    '',
    `- 试验：${activeMeta.value.eyebrow}`,
    `- 后端判定：${result.value.passed ? '通过' : '未通过'}`,
    `- 教学输入长度：${inputLength.value} 字符（不导出原文）`,
    '',
    '## 后端步骤',
    ...safeSteps.value.map((step, index) => `${index + 1}. ${step}`),
    '',
    '## 脱敏结果',
    ...safeValues.value.map(([key, value]) => `- ${key}：${value}`),
    '',
    '> 本报告不包含教学输入原文、密钥、口令或完整密码中间值。',
  ]
}

function downloadReport(): void {
  if (!result.value || isExporting.value) return
  isExporting.value = true
  try {
    const blobUrl = globalThis.URL.createObjectURL(
      new globalThis.Blob([reportLines().join('\n')], { type: 'text/markdown;charset=utf-8' }),
    )
    const anchor = globalThis.document.createElement('a')
    anchor.href = blobUrl
    anchor.download = `cryptocampus-${experiment.value}-report.md`
    anchor.click()
    globalThis.URL.revokeObjectURL(blobUrl)
  } finally {
    isExporting.value = false
  }
}
</script>

<template>
  <section class="algorithm-lab" aria-labelledby="algorithm-lab-title">
    <header class="lab-heading">
      <div>
        <router-link class="back-link" :to="{ name: 'inspect' }">
          <el-icon><ArrowLeft /></el-icon>
          返回密码透视
        </router-link>
        <p class="eyebrow">教学视图 · FR-09</p>
        <h1 id="algorithm-lab-title">通用算法试验台</h1>
        <p>输入只发送给后端 openHiTLS 链路；浏览器负责交互与脱敏展示。</p>
      </div>
      <div class="trust-statement">
        <strong>计算边界</strong>
        <span>前端不实现 SM3、SM4 或随机数生成</span>
      </div>
    </header>

    <nav class="experiment-switcher" aria-label="选择算法试验">
      <button
        type="button"
        :class="{ active: experiment === 'sm4_mode_compare' }"
        :aria-pressed="experiment === 'sm4_mode_compare'"
        data-testid="mode-sm4"
        @click="chooseExperiment('sm4_mode_compare')"
      >
        <span>01</span><strong>SM4 模式对比</strong
        ><small class="ecb-risk-label">ECB 风险对照 · 仅限教学</small>
      </button>
      <button
        type="button"
        :class="{ active: experiment === 'sm3_avalanche' }"
        :aria-pressed="experiment === 'sm3_avalanche'"
        data-testid="mode-sm3"
        @click="chooseExperiment('sm3_avalanche')"
      >
        <span>02</span><strong>SM3 雪崩效应</strong><small>观察单比特变化扩散</small>
      </button>
    </nav>

    <div class="lab-grid">
      <section class="input-panel" aria-labelledby="experiment-input-title">
        <div class="panel-heading">
          <div>
            <p class="eyebrow">{{ activeMeta.eyebrow }}</p>
            <h2 id="experiment-input-title">{{ activeMeta.title }}</h2>
          </div>
          <el-tag effect="plain">最大 1 MiB</el-tag>
        </div>
        <p class="panel-description">{{ activeMeta.description }}</p>

        <label for="experiment-input">教学输入</label>
        <el-input
          id="experiment-input"
          v-model="input"
          type="textarea"
          :rows="8"
          resize="none"
          :maxlength="MAX_INPUT_LENGTH + 1"
          data-testid="experiment-input"
          aria-describedby="input-boundary"
        />
        <div id="input-boundary" class="input-boundary" :class="{ danger: inputTooLong }">
          <span>不得粘贴真实业务明文、口令或密钥</span>
          <span>{{ inputLength.toLocaleString() }} / {{ MAX_INPUT_LENGTH.toLocaleString() }}</span>
        </div>

        <div class="input-actions">
          <el-button plain @click="useExample">使用示例</el-button>
          <el-button :icon="RefreshLeft" text @click="reset">清空重置</el-button>
          <el-button
            type="primary"
            :icon="VideoPlay"
            :loading="isRunning"
            :disabled="inputTooLong"
            data-testid="run-experiment"
            @click="runExperiment"
          >
            交给后端运行
          </el-button>
        </div>
      </section>

      <section class="result-panel" aria-labelledby="experiment-result-title" aria-live="polite">
        <div class="panel-heading">
          <div>
            <p class="eyebrow">后端返回 · 已脱敏</p>
            <h2 id="experiment-result-title">试验证据</h2>
          </div>
          <el-button
            v-if="result"
            plain
            :icon="Download"
            :loading="isExporting"
            data-testid="export-report"
            @click="downloadReport"
          >
            导出报告
          </el-button>
        </div>

        <el-alert
          v-if="errorMessage"
          title="试验未完成"
          :description="errorMessage"
          type="warning"
          :closable="false"
          show-icon
        />
        <div v-else-if="isRunning" class="result-empty busy" role="status">
          <span class="pulse-ring"></span>
          <strong>密码引擎正在运行</strong>
          <p>等待后端返回脱敏步骤，不在本地预先生成结果。</p>
        </div>
        <div v-else-if="!result" class="result-empty">
          <span class="empty-glyph">∴</span>
          <strong>尚未产生试验结果</strong>
          <p>选择试验、检查教学输入，然后交给后端运行。</p>
        </div>
        <template v-else>
          <div class="result-status" :class="result.passed ? 'passed' : 'failed'">
            <span>{{ result.passed ? 'PASS' : 'CHECK' }}</span>
            <div>
              <strong>{{ result.passed ? '后端判定：试验通过' : '后端判定：试验未通过' }}</strong>
              <small>{{ result.experiment }}</small>
            </div>
          </div>

          <div v-if="avalancheMetric" class="avalanche-meter" data-testid="avalanche-meter">
            <div class="meter-copy">
              <span>摘要翻转</span>
              <strong>{{ avalancheMetric.changed }} / {{ avalancheMetric.total }} bit</strong>
            </div>
            <div class="meter-track" aria-hidden="true">
              <span :style="{ width: `${avalancheMetric.percent}%` }"></span>
            </div>
            <small>{{ avalancheMetric.percent.toFixed(1) }}% · 统计值由后端提供</small>
          </div>

          <ol class="result-steps" aria-label="后端试验步骤">
            <li v-for="(step, index) in safeSteps" :key="`${index}-${step}`">
              <span>{{ String(index + 1).padStart(2, '0') }}</span>
              <p>{{ step }}</p>
            </li>
          </ol>

          <dl class="redacted-values" aria-label="脱敏结果字段">
            <div v-for="([key, value], index) in safeValues" :key="`${key}-${index}`">
              <dt>{{ key }}</dt>
              <dd>{{ value }}</dd>
            </div>
          </dl>
          <p v-if="safeValues.length === 0" class="no-values">后端未返回可展示的脱敏字段。</p>
        </template>
      </section>
    </div>
  </section>
</template>

<style scoped>
.algorithm-lab {
  display: grid;
  gap: 16px;
}

.lab-heading,
.panel-heading,
.input-actions,
.input-boundary,
.result-status {
  display: flex;
  align-items: center;
}

.lab-heading {
  justify-content: space-between;
  gap: 24px;
}

.lab-heading h1,
.panel-heading h2,
.lab-heading p {
  margin: 0;
}

.lab-heading h1 {
  margin-top: 4px;
  color: var(--cc-primary-dark);
  font-size: clamp(26px, 3vw, 38px);
  letter-spacing: -0.035em;
}

.lab-heading > div:first-child > p:last-child,
.panel-description {
  color: var(--cc-muted);
  line-height: 1.6;
}

.back-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 14px;
  color: var(--cc-primary);
  font-size: 13px;
  text-decoration: none;
}

.eyebrow {
  color: var(--cc-primary);
  font-size: 11px;
  font-weight: 750;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.trust-statement {
  display: grid;
  min-width: 276px;
  gap: 5px;
  padding: 15px 18px;
  border: 1px solid #c8d7ea;
  border-radius: 12px;
  background: linear-gradient(135deg, #f8fbff, #eef4fc);
}

.trust-statement strong {
  color: var(--cc-primary-dark);
  font-size: 12px;
}

.trust-statement span {
  color: var(--cc-muted);
  font-size: 11px;
}

.experiment-switcher {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.experiment-switcher button {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 2px 12px;
  padding: 14px 16px;
  border: 1px solid var(--cc-line);
  border-radius: 12px;
  color: var(--cc-ink);
  background: #fff;
  cursor: pointer;
  text-align: left;
  transition: 160ms ease;
}

.experiment-switcher button:hover,
.experiment-switcher button.active {
  border-color: #82aee4;
  box-shadow: 0 7px 20px rgb(18 63 125 / 8%);
}

.experiment-switcher button.active {
  background: linear-gradient(100deg, #edf4fd, #fff 62%);
}

.experiment-switcher button > span {
  grid-row: span 2;
  color: #8fa5c0;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 12px;
}

.experiment-switcher strong {
  color: var(--cc-primary-dark);
  font-size: 14px;
}

.experiment-switcher small {
  color: var(--cc-muted);
}

.experiment-switcher .ecb-risk-label {
  color: var(--cc-danger);
  font-weight: 700;
}

.lab-grid {
  display: grid;
  grid-template-columns: minmax(360px, 0.9fr) minmax(420px, 1.1fr);
  gap: 16px;
}

.input-panel,
.result-panel {
  min-width: 0;
  min-height: 490px;
  padding: 20px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: var(--cc-card);
  box-shadow: var(--cc-shadow);
}

.panel-heading {
  justify-content: space-between;
  gap: 16px;
}

.panel-heading h2 {
  margin-top: 4px;
  color: var(--cc-primary-dark);
  font-size: 20px;
}

.panel-description {
  min-height: 45px;
  margin: 12px 0 18px;
  font-size: 13px;
}

.input-panel label {
  display: block;
  margin-bottom: 7px;
  color: var(--cc-ink);
  font-size: 12px;
  font-weight: 700;
}

.input-panel :deep(textarea) {
  font-family: 'Cascadia Code', Consolas, monospace;
  line-height: 1.65;
}

.input-boundary {
  justify-content: space-between;
  gap: 12px;
  margin-top: 8px;
  color: var(--cc-muted);
  font-size: 11px;
}

.input-boundary.danger {
  color: var(--cc-danger);
  font-weight: 700;
}

.input-actions {
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 6px;
  margin-top: 20px;
}

.result-panel {
  display: flex;
  flex-direction: column;
}

.result-empty {
  display: grid;
  flex: 1;
  place-content: center;
  justify-items: center;
  padding: 36px;
  color: var(--cc-muted);
  text-align: center;
}

.result-empty strong {
  margin-top: 12px;
  color: var(--cc-primary-dark);
}

.result-empty p {
  max-width: 330px;
  margin: 7px 0 0;
  font-size: 12px;
  line-height: 1.6;
}

.empty-glyph {
  display: grid;
  width: 58px;
  height: 58px;
  place-items: center;
  border: 1px dashed #9fb5d0;
  border-radius: 50%;
  color: var(--cc-primary);
  font-family: Georgia, serif;
  font-size: 30px;
}

.pulse-ring {
  width: 46px;
  height: 46px;
  border: 3px solid #c5d7ec;
  border-top-color: var(--cc-primary);
  border-radius: 50%;
  animation: spin 900ms linear infinite;
}

.result-status {
  gap: 12px;
  margin-top: 17px;
  padding: 12px;
  border-radius: 10px;
}

.result-status.passed {
  color: #176f40;
  background: #eaf7ef;
}

.result-status.failed {
  color: #8b3028;
  background: #fff0ef;
}

.result-status > span {
  padding: 5px 8px;
  border: 1px solid currentcolor;
  border-radius: 5px;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 10px;
  font-weight: 800;
}

.result-status div {
  display: grid;
  gap: 3px;
}

.result-status small {
  opacity: 0.75;
}

.avalanche-meter {
  margin-top: 14px;
  padding: 14px;
  border: 1px solid #d8e4f2;
  border-radius: 10px;
  background: #f7faff;
}

.meter-copy {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  color: var(--cc-muted);
  font-size: 11px;
}

.meter-copy strong {
  color: var(--cc-primary-dark);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 16px;
}

.meter-track {
  height: 10px;
  margin: 10px 0 7px;
  overflow: hidden;
  border-radius: 999px;
  background: #dfe8f4;
}

.meter-track span {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, #1e5cb3, #7654c7);
}

.avalanche-meter small {
  color: var(--cc-muted);
}

.result-steps {
  display: grid;
  max-height: 170px;
  gap: 7px;
  margin: 14px 0 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
}

.result-steps li {
  display: grid;
  grid-template-columns: 28px 1fr;
  gap: 9px;
  align-items: start;
  padding: 8px 10px;
  border-left: 2px solid #abc4e3;
  background: #f8fafc;
}

.result-steps span {
  color: var(--cc-primary);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 10px;
}

.result-steps p {
  margin: 0;
  color: #334155;
  font-size: 12px;
  line-height: 1.45;
}

.redacted-values {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  margin: 14px 0 0;
}

.redacted-values div {
  min-width: 0;
  padding: 9px 10px;
  border: 1px solid #e1e7ee;
  border-radius: 8px;
}

.redacted-values dt {
  overflow: hidden;
  color: var(--cc-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.redacted-values dd {
  overflow-wrap: anywhere;
  margin: 5px 0 0;
  color: var(--cc-ink);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 11px;
}

.no-values {
  margin: 18px 0 0;
  color: var(--cc-muted);
  font-size: 12px;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 980px) {
  .lab-grid {
    grid-template-columns: 1fr;
  }

  .input-panel,
  .result-panel {
    min-height: auto;
  }
}

@media (max-width: 680px) {
  .lab-heading {
    align-items: stretch;
    flex-direction: column;
  }

  .trust-statement,
  .lab-grid {
    min-width: 0;
  }

  .experiment-switcher,
  .redacted-values {
    grid-template-columns: 1fr;
  }

  .input-actions {
    justify-content: stretch;
  }

  .input-actions :deep(.el-button) {
    flex: 1;
    margin-left: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .experiment-switcher button {
    transition: none;
  }

  .pulse-ring {
    animation-duration: 2s;
  }
}
</style>
