<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ArrowLeft,
  ArrowRight,
  Download,
  Refresh,
  RefreshLeft,
  VideoPause,
  VideoPlay,
  Warning,
} from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import {
  exportInspectReport,
  getInspectRecord,
  listInspectRecordMetadata,
  listInspectRecords,
  type InspectMetadataPage,
  type InspectRecord,
} from '@/api/inspect'
import { useSessionStore } from '@/stores/session'

type InspectStep = InspectRecord['steps'][number]

const route = useRoute()
const router = useRouter()
const session = useSessionStore()

const records = shallowRef<InspectRecord[]>([])
const recordsTotal = ref(0)
const currentPage = ref(1)
const pageSize = 20
const selectedRecord = shallowRef<InspectRecord | null>(null)
const privilegedMetadata = shallowRef<InspectMetadataPage | null>(null)
const isListLoading = ref(false)
const isRecordLoading = ref(false)
const isMetadataLoading = ref(false)
const isExporting = ref(false)
const listError = ref('')
const recordError = ref('')
const metadataError = ref('')
const exportError = ref('')
const currentStepIndex = ref(0)
const isPlaying = ref(false)
let playbackTimer: number | undefined

const operationLabels: Readonly<Record<string, string>> = Object.freeze({
  drop_create: '密信加密',
  drop_extract: '密信解密',
  hole_credential: '树洞凭证签发',
  hole_post: '树洞匿名发布',
  vote_ballot: '匿名投票',
  seal_create: '文件盖章',
  seal_verify: '文件验真',
  chat_handshake: '聊天密钥协商',
})

const valueLabels: Readonly<Record<string, string>> = Object.freeze({
  input_length: '输入长度',
  input_bytes: '输入字节数',
  output_length: '输出长度',
  output_bytes: '输出字节数',
  duration_ms: '耗时',
  elapsed_ms: '耗时',
  iv_length: 'IV 长度',
  nonce_length: 'Nonce 长度',
  tag_length: 'Tag 长度',
  digest_prefix: '摘要前缀',
  output_prefix: '输出前缀',
  key_fingerprint: '密钥指纹',
  certificate_subject: '证书主体',
  mode: '工作模式',
  curve: '曲线',
})

const blockedValueKey =
  /(password|passphrase|plaintext|plain_text|private|secret|session[_-]?key|refresh[_-]?token|access[_-]?token|kek|credential|full[_-]?intermediate)/i

const isPrivileged = computed(
  () => session.currentUser?.role === 'admin' || session.currentUser?.role === 'teacher',
)
const sortedSteps = computed(() =>
  [...(selectedRecord.value?.steps ?? [])].sort((left, right) => left.order - right.order),
)
const activeStep = computed(() => sortedSteps.value[currentStepIndex.value] ?? null)
const failedStepIndex = computed(() =>
  sortedSteps.value.findIndex((step) => step.result === 'failed'),
)
const recordOutcome = computed(() => {
  if (!selectedRecord.value) return { label: '状态未知', type: 'info' as const }
  if (selectedRecord.value.steps.some((step) => step.result === 'failed')) {
    return { label: '流程失败', type: 'danger' as const }
  }
  if (selectedRecord.value.steps.some((step) => step.result === 'skipped')) {
    return { label: '部分跳过', type: 'warning' as const }
  }
  return { label: '流程通过', type: 'success' as const }
})
const activeStepValues = computed(() => safeRedactedEntries(activeStep.value))

function operationLabel(operation: string): string {
  return operationLabels[operation] ?? operation
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '时间未知'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date)
}

function recordStatus(record: InspectRecord): {
  label: string
  type: 'success' | 'warning' | 'danger' | 'info'
} {
  if (record.steps.some((step) => step.result === 'failed')) {
    return { label: '失败', type: 'danger' }
  }
  if (record.steps.some((step) => step.result === 'skipped')) {
    return { label: '有跳过', type: 'warning' }
  }
  if (record.steps.length === 0) return { label: '无步骤', type: 'info' }
  return { label: '通过', type: 'success' }
}

function stepStatusLabel(result: InspectStep['result']): string {
  return { passed: '通过', failed: '失败', skipped: '已跳过' }[result]
}

function safeRedactedEntries(step: InspectStep | null): ReadonlyArray<[string, string]> {
  if (!step) return []

  return Object.entries(step.redacted_values)
    .filter(([key]) => !blockedValueKey.test(key))
    .map(([key, value]) => {
      const label = valueLabels[key] ?? key.replaceAll('_', ' ')
      if (typeof value === 'number') {
        return [label, key.endsWith('_ms') ? `${value} ms` : String(value)] as [string, string]
      }
      if (typeof value === 'boolean') return [label, value ? '是' : '否'] as [string, string]
      if (typeof value === 'string') {
        const normalized = value.trim()
        return [label, normalized.length > 120 ? `${normalized.slice(0, 117)}…` : normalized] as [
          string,
          string,
        ]
      }
      return [label, '已脱敏结构'] as [string, string]
    })
}

function listFailureMessage(error: unknown): string {
  if (error instanceof ApiError && (error.status === 404 || error.status === 501)) {
    return '密码透视服务暂未开放。'
  }
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function recordFailureMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) return '你无权查看这条透视记录。'
  if (error instanceof ApiError && error.status === 404) return '记录不存在、已过期或不可见。'
  if (error instanceof ApiError && error.status === 501) return '密码透视服务暂未开放。'
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function stopPlayback(): void {
  if (playbackTimer) globalThis.clearInterval(playbackTimer)
  playbackTimer = undefined
  isPlaying.value = false
}

function startPlayback(): void {
  if (isPlaying.value || sortedSteps.value.length < 2) return
  if (currentStepIndex.value >= sortedSteps.value.length - 1) currentStepIndex.value = 0
  isPlaying.value = true
  playbackTimer = globalThis.setInterval(() => {
    if (currentStepIndex.value >= sortedSteps.value.length - 1) {
      stopPlayback()
      return
    }
    currentStepIndex.value += 1
  }, 900)
}

function togglePlayback(): void {
  if (isPlaying.value) stopPlayback()
  else startPlayback()
}

function showPreviousStep(): void {
  stopPlayback()
  currentStepIndex.value = Math.max(0, currentStepIndex.value - 1)
}

function showNextStep(): void {
  stopPlayback()
  currentStepIndex.value = Math.min(sortedSteps.value.length - 1, currentStepIndex.value + 1)
}

function replay(): void {
  stopPlayback()
  currentStepIndex.value = 0
  startPlayback()
}

function focusFailedStep(): void {
  if (failedStepIndex.value < 0) return
  stopPlayback()
  currentStepIndex.value = failedStepIndex.value
}

function selectStep(index: number): void {
  stopPlayback()
  currentStepIndex.value = index
}

async function selectRecord(recordId: string): Promise<void> {
  if (String(route.params.recordId ?? '') === recordId) {
    await loadRecord(recordId)
    return
  }
  await router.replace({ name: 'inspect-record', params: { recordId } })
}

async function loadRecords(page = currentPage.value): Promise<void> {
  if (!session.accessToken || isListLoading.value) return
  isListLoading.value = true
  listError.value = ''
  try {
    const response = await listInspectRecords(session.accessToken, page, pageSize)
    records.value = response.items
    recordsTotal.value = response.total
    currentPage.value = response.page
    if (!route.params.recordId && response.items[0]) await selectRecord(response.items[0].id)
  } catch (error) {
    records.value = []
    recordsTotal.value = 0
    listError.value = listFailureMessage(error)
  } finally {
    isListLoading.value = false
  }
}

async function loadRecord(recordId: string): Promise<void> {
  if (!session.accessToken || isRecordLoading.value) return
  stopPlayback()
  isRecordLoading.value = true
  recordError.value = ''
  exportError.value = ''
  currentStepIndex.value = 0
  try {
    selectedRecord.value = await getInspectRecord(recordId, session.accessToken)
  } catch (error) {
    selectedRecord.value = null
    recordError.value = recordFailureMessage(error)
  } finally {
    isRecordLoading.value = false
  }
}

async function loadPrivilegedMetadata(): Promise<void> {
  if (!session.accessToken || !isPrivileged.value || isMetadataLoading.value) return
  isMetadataLoading.value = true
  metadataError.value = ''
  try {
    privilegedMetadata.value = await listInspectRecordMetadata(session.accessToken)
  } catch (error) {
    privilegedMetadata.value = null
    metadataError.value = listFailureMessage(error)
  } finally {
    isMetadataLoading.value = false
  }
}

async function changePage(page: number): Promise<void> {
  await loadRecords(page)
}

async function downloadReport(): Promise<void> {
  if (!selectedRecord.value || selectedRecord.value.owner !== 'self' || !session.accessToken) return
  isExporting.value = true
  exportError.value = ''
  try {
    const report = await exportInspectReport(selectedRecord.value.id, session.accessToken)
    const blobUrl = globalThis.URL.createObjectURL(
      new globalThis.Blob([report], { type: 'text/markdown;charset=utf-8' }),
    )
    const anchor = globalThis.document.createElement('a')
    anchor.href = blobUrl
    anchor.download = `cryptocampus-inspect-${selectedRecord.value.id.slice(0, 8)}.md`
    anchor.click()
    globalThis.URL.revokeObjectURL(blobUrl)
  } catch (error) {
    exportError.value = recordFailureMessage(error)
  } finally {
    isExporting.value = false
  }
}

watch(
  () => route.params.recordId,
  (recordId) => {
    if (typeof recordId === 'string' && recordId) void loadRecord(recordId)
    else {
      stopPlayback()
      selectedRecord.value = null
      recordError.value = ''
    }
  },
  { immediate: true },
)

onMounted(() => {
  void loadRecords()
  void loadPrivilegedMetadata()
})

onBeforeUnmount(stopPlayback)
</script>

<template>
  <section class="inspect-dashboard" aria-labelledby="inspect-title">
    <div class="page-heading inspect-heading">
      <div>
        <p class="eyebrow">教学视图 · FR-09</p>
        <h1 id="inspect-title">密码透视</h1>
        <p>回放真实业务的密码流程；前端只展示后端提供的脱敏步骤，不重算密码中间值。</p>
      </div>
      <div class="inspect-heading-actions">
        <el-tag type="success" effect="plain" round>记录已脱敏</el-tag>
        <el-button plain @click="router.push({ name: 'inspect-tlcp' })">TLCP 时序</el-button>
        <el-button plain @click="router.push({ name: 'inspect-experiments' })">
          算法试验台
        </el-button>
        <el-button :icon="Refresh" :loading="isListLoading" @click="loadRecords()">
          刷新记录
        </el-button>
      </div>
    </div>

    <div class="inspect-workbench">
      <aside class="record-panel" aria-labelledby="record-list-title">
        <div class="panel-heading compact-heading">
          <div>
            <p class="eyebrow">操作历史</p>
            <h2 id="record-list-title">我的透视记录</h2>
          </div>
          <span>{{ recordsTotal }} 条</span>
        </div>

        <p class="privacy-boundary">
          {{ isPrivileged ? '本人记录可回放；他人仅展示授权元信息。' : '仅显示本人记录。' }}
        </p>

        <el-skeleton v-if="isListLoading && records.length === 0" :rows="6" animated />
        <el-alert
          v-else-if="listError"
          title="无法读取透视记录"
          :description="listError"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-empty
          v-else-if="records.length === 0"
          description="暂无可回放的透视记录"
          :image-size="68"
        />
        <div v-else class="record-list" aria-label="本人密码透视记录">
          <button
            v-for="record in records"
            :key="record.id"
            class="record-item"
            :class="{ active: selectedRecord?.id === record.id }"
            type="button"
            :aria-pressed="selectedRecord?.id === record.id"
            @click="selectRecord(record.id)"
          >
            <span class="record-item-topline">
              <strong>{{ operationLabel(record.operation) }}</strong>
              <el-tag :type="recordStatus(record).type" effect="light" size="small">
                {{ recordStatus(record).label }}
              </el-tag>
            </span>
            <span class="record-item-meta">
              <time :datetime="record.created_at">{{ formatDate(record.created_at) }}</time>
              <span>{{ record.steps.length }} 个步骤</span>
            </span>
            <code>{{ record.id.slice(0, 8) }}…</code>
          </button>
        </div>

        <el-pagination
          v-if="recordsTotal > pageSize"
          class="record-pagination"
          small
          background
          layout="prev, pager, next"
          :current-page="currentPage"
          :page-size="pageSize"
          :total="recordsTotal"
          @current-change="changePage"
        />

        <section v-if="isPrivileged" class="metadata-panel" aria-labelledby="metadata-title">
          <div class="metadata-heading">
            <h3 id="metadata-title">教学审阅元信息</h3>
            <el-tag type="info" size="small" effect="plain">不含中间值</el-tag>
          </div>
          <el-skeleton v-if="isMetadataLoading" :rows="2" animated />
          <p v-else-if="metadataError" class="inline-error" role="alert">{{ metadataError }}</p>
          <p v-else-if="!privilegedMetadata?.items.length" class="metadata-empty">
            暂无他人记录元信息
          </p>
          <ul v-else class="metadata-list">
            <li v-for="item in privilegedMetadata.items" :key="item.id">
              <strong>{{ operationLabel(item.operation) }}</strong>
              <span
                >{{ formatDate(item.created_at) }} · 用户
                {{ item.owner_user_id.slice(0, 8) }}…</span
              >
            </li>
          </ul>
        </section>
      </aside>

      <main class="playback-panel" aria-labelledby="playback-title">
        <el-skeleton v-if="isRecordLoading" :rows="10" animated />
        <el-alert
          v-else-if="recordError"
          title="无法打开透视记录"
          :description="recordError"
          type="warning"
          :closable="false"
          show-icon
        />
        <div v-else-if="!selectedRecord" class="record-empty-state">
          <el-empty description="请选择一条记录开始回放" :image-size="88" />
        </div>
        <template v-else>
          <header class="playback-header">
            <div>
              <p class="eyebrow">操作回放</p>
              <h2 id="playback-title">{{ operationLabel(selectedRecord.operation) }}</h2>
              <p>
                记录 {{ selectedRecord.id.slice(0, 8) }}… ·
                <time :datetime="selectedRecord.created_at">{{
                  formatDate(selectedRecord.created_at)
                }}</time>
              </p>
            </div>
            <div class="record-actions">
              <el-tag :type="recordOutcome.type" effect="light">{{ recordOutcome.label }}</el-tag>
              <el-button
                :icon="Download"
                :loading="isExporting"
                :disabled="selectedRecord.owner !== 'self'"
                @click="downloadReport"
              >
                导出报告素材
              </el-button>
            </div>
          </header>

          <el-alert
            v-if="selectedRecord.owner !== 'self'"
            class="ownership-alert"
            title="当前记录仅允许查看授权内容，不可导出"
            type="info"
            :closable="false"
            show-icon
          />
          <p v-if="exportError" class="inline-error export-error" role="alert">{{ exportError }}</p>

          <div class="step-flow" aria-label="密码流程步骤">
            <button
              v-for="(step, index) in sortedSteps"
              :key="`${step.order}-${step.name}`"
              class="flow-step"
              :class="[
                `result-${step.result}`,
                { active: index === currentStepIndex, complete: index < currentStepIndex },
              ]"
              type="button"
              :aria-current="index === currentStepIndex ? 'step' : undefined"
              @click="selectStep(index)"
            >
              <span class="step-order">{{ step.order }}</span>
              <strong>{{ step.name }}</strong>
              <small>{{ step.algorithm }}</small>
              <span class="step-result">{{ stepStatusLabel(step.result) }}</span>
            </button>
          </div>

          <div class="playback-controls" aria-label="回放控制">
            <el-button
              :icon="ArrowLeft"
              :disabled="currentStepIndex === 0"
              aria-label="上一步"
              @click="showPreviousStep"
            >
              上一步
            </el-button>
            <el-button
              type="primary"
              :icon="isPlaying ? VideoPause : VideoPlay"
              :disabled="sortedSteps.length < 2"
              data-testid="playback-toggle"
              @click="togglePlayback"
            >
              {{ isPlaying ? '暂停' : '播放' }}
            </el-button>
            <el-button
              :icon="ArrowRight"
              :disabled="currentStepIndex >= sortedSteps.length - 1"
              aria-label="下一步"
              @click="showNextStep"
            >
              下一步
            </el-button>
            <el-button :icon="RefreshLeft" :disabled="sortedSteps.length < 2" @click="replay">
              重播
            </el-button>
            <el-button
              v-if="failedStepIndex >= 0"
              class="failure-locator"
              type="danger"
              plain
              :icon="Warning"
              @click="focusFailedStep"
            >
              定位失败步骤
            </el-button>
            <span class="step-counter">
              {{ sortedSteps.length ? currentStepIndex + 1 : 0 }} / {{ sortedSteps.length }}
            </span>
          </div>

          <section v-if="activeStep" class="step-detail" aria-live="polite">
            <div class="step-detail-heading">
              <div>
                <span>当前步骤 {{ activeStep.order }}</span>
                <h3>{{ activeStep.name }}</h3>
              </div>
              <div class="step-detail-tags">
                <el-tag effect="plain">{{ activeStep.algorithm }}</el-tag>
                <el-tag
                  :type="
                    activeStep.result === 'passed'
                      ? 'success'
                      : activeStep.result === 'failed'
                        ? 'danger'
                        : 'warning'
                  "
                >
                  {{ stepStatusLabel(activeStep.result) }}
                </el-tag>
              </div>
            </div>

            <dl v-if="activeStepValues.length" class="redacted-value-grid">
              <div v-for="[label, value] in activeStepValues" :key="label">
                <dt>{{ label }}</dt>
                <dd>{{ value }}</dd>
              </div>
            </dl>
            <div v-else class="no-redacted-values">该步骤没有可展示的脱敏中间值。</div>

            <div class="privacy-note">
              <strong>脱敏边界</strong>
              <span
                >仅展示长度、算法、耗时、摘要前缀等教学信息；完整密钥、口令、令牌与业务明文不会显示。</span
              >
            </div>
          </section>
        </template>
      </main>
    </div>
  </section>
</template>

<style scoped>
.inspect-dashboard {
  display: grid;
  gap: 22px;
}

.inspect-heading {
  margin-bottom: 0;
}

.inspect-heading-actions,
.record-actions,
.playback-controls,
.step-detail-tags {
  display: flex;
  align-items: center;
  gap: 10px;
}

.inspect-workbench {
  display: grid;
  grid-template-columns: 292px minmax(0, 1fr);
  gap: 16px;
  min-height: 590px;
}

.record-panel,
.playback-panel {
  min-width: 0;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: var(--cc-card);
  box-shadow: var(--cc-shadow);
}

.record-panel {
  display: flex;
  min-height: 590px;
  flex-direction: column;
  padding: 18px;
}

.panel-heading,
.playback-header,
.step-detail-heading,
.record-item-topline,
.record-item-meta,
.metadata-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.compact-heading h2,
.playback-header h2,
.step-detail-heading h3,
.metadata-heading h3 {
  margin: 3px 0 0;
  color: var(--cc-primary-dark);
}

.compact-heading h2 {
  font-size: 18px;
}

.compact-heading > span {
  color: var(--cc-muted);
  font-size: 12px;
}

.privacy-boundary {
  margin: 13px 0;
  padding: 8px 10px;
  border-left: 3px solid var(--cc-primary);
  border-radius: 0 6px 6px 0;
  color: var(--cc-muted);
  background: #f6f8fb;
  font-size: 11px;
  line-height: 1.55;
}

.record-list {
  display: grid;
  max-height: 420px;
  gap: 8px;
  overflow-y: auto;
  padding-right: 3px;
}

.record-item {
  display: grid;
  width: 100%;
  gap: 7px;
  padding: 11px 12px;
  border: 1px solid #e1e6ed;
  border-radius: 9px;
  color: var(--cc-ink);
  background: #fff;
  cursor: pointer;
  text-align: left;
  transition:
    border-color 160ms ease,
    background-color 160ms ease,
    box-shadow 160ms ease;
}

.record-item:hover {
  border-color: #9ab9df;
  background: #f8fbff;
}

.record-item.active {
  border-color: var(--cc-primary);
  background: var(--cc-primary-light);
  box-shadow: 0 0 0 2px rgb(30 92 179 / 10%);
}

.record-item strong {
  overflow: hidden;
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.record-item-meta {
  color: var(--cc-muted);
  font-size: 10px;
}

.record-item code {
  color: #526176;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 10px;
}

.record-pagination {
  justify-content: center;
  margin-top: 13px;
}

.metadata-panel {
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid #e5e9ef;
}

.metadata-heading h3 {
  font-size: 13px;
}

.metadata-list {
  display: grid;
  gap: 8px;
  margin: 10px 0 0;
  padding: 0;
  list-style: none;
}

.metadata-list li {
  display: grid;
  gap: 3px;
  padding: 8px 9px;
  border-radius: 7px;
  background: #f7f9fc;
}

.metadata-list strong {
  font-size: 11px;
}

.metadata-list span,
.metadata-empty {
  color: var(--cc-muted);
  font-size: 10px;
}

.playback-panel {
  padding: 22px;
}

.playback-header {
  align-items: flex-start;
  padding-bottom: 17px;
  border-bottom: 1px solid #e6eaf0;
}

.playback-header h2 {
  font-size: 22px;
}

.playback-header p:last-child {
  margin: 6px 0 0;
  color: var(--cc-muted);
  font-size: 11px;
}

.record-actions {
  flex-wrap: wrap;
  justify-content: flex-end;
}

.ownership-alert {
  margin-top: 14px;
}

.step-flow {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
  gap: 8px;
  margin-top: 18px;
}

.flow-step {
  position: relative;
  display: grid;
  min-width: 0;
  min-height: 112px;
  place-items: center;
  align-content: center;
  gap: 4px;
  padding: 10px 7px;
  border: 1px solid var(--cc-line);
  border-radius: 8px;
  color: var(--cc-ink);
  background: #fff;
  cursor: pointer;
  text-align: center;
  transition:
    border-color 180ms ease,
    background-color 180ms ease,
    box-shadow 180ms ease;
}

.flow-step:hover {
  border-color: #9ab9df;
}

.flow-step.complete,
.flow-step.result-passed.active {
  border-color: #74b990;
  background: #eef9f2;
}

.flow-step.result-failed {
  border-color: #e2a8a3;
  background: #fff5f4;
}

.flow-step.result-skipped {
  border-color: #dfc88b;
  background: #fffaf0;
}

.flow-step.active {
  box-shadow: 0 0 0 3px rgb(30 92 179 / 13%);
}

.flow-step.result-failed.active {
  box-shadow: 0 0 0 3px rgb(200 56 46 / 13%);
}

.step-order {
  display: grid;
  width: 23px;
  height: 23px;
  place-items: center;
  border-radius: 50%;
  color: #fff;
  background: var(--cc-primary);
  font-size: 11px;
  font-weight: 750;
}

.result-failed .step-order {
  background: var(--cc-danger);
}

.result-passed.complete .step-order,
.result-passed.active .step-order {
  background: var(--cc-success);
}

.result-skipped .step-order {
  background: #a77413;
}

.flow-step strong,
.flow-step small {
  display: block;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.flow-step strong {
  font-size: 11px;
}

.flow-step small,
.step-result {
  color: var(--cc-muted);
  font-size: 9px;
}

.playback-controls {
  flex-wrap: wrap;
  margin: 15px 0;
  padding: 12px;
  border: 1px solid #e0e6ed;
  border-radius: 9px;
  background: #f7f9fc;
}

.failure-locator {
  margin-left: auto;
}

.step-counter {
  min-width: 48px;
  color: var(--cc-muted);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 11px;
  text-align: right;
}

.step-detail {
  padding: 18px;
  border: 1px solid #cbd5e1;
  border-radius: 10px;
  background: #fff;
}

.step-detail-heading > div:first-child > span {
  color: var(--cc-muted);
  font-size: 10px;
}

.step-detail-heading h3 {
  font-size: 17px;
}

.redacted-value-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  margin: 15px 0 0;
  overflow: hidden;
  border: 1px solid #394556;
  border-radius: 8px;
  background: #394556;
}

.redacted-value-grid > div {
  min-width: 0;
  padding: 11px 12px;
  background: #222831;
}

.redacted-value-grid dt {
  color: #9eacbd;
  font-size: 9px;
}

.redacted-value-grid dd {
  margin: 5px 0 0;
  overflow-wrap: anywhere;
  color: #d7e0ea;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 10px;
  line-height: 1.5;
}

.no-redacted-values {
  margin-top: 15px;
  padding: 20px;
  border-radius: 8px;
  color: #aeb9c7;
  background: #222831;
  font-size: 11px;
  text-align: center;
}

.privacy-note {
  display: flex;
  gap: 9px;
  margin-top: 14px;
  padding: 9px 11px;
  border-left: 3px solid var(--cc-primary);
  border-radius: 0 7px 7px 0;
  color: var(--cc-muted);
  background: #f6f8fb;
  font-size: 10px;
  line-height: 1.55;
}

.privacy-note strong {
  flex: 0 0 auto;
  color: var(--cc-primary-dark);
}

.inline-error {
  margin: 9px 0 0;
  color: #9b3028;
  font-size: 11px;
  line-height: 1.5;
}

.export-error {
  text-align: right;
}

.record-empty-state {
  display: grid;
  min-height: 500px;
  place-items: center;
}

@media (max-width: 1080px) {
  .inspect-workbench {
    grid-template-columns: 250px minmax(0, 1fr);
  }

  .redacted-value-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 840px) {
  .inspect-workbench {
    grid-template-columns: 1fr;
  }

  .record-panel {
    min-height: auto;
  }

  .record-list {
    max-height: 280px;
  }

  .playback-header,
  .step-detail-heading,
  .inspect-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .record-actions {
    justify-content: flex-start;
  }
}

@media (prefers-reduced-motion: reduce) {
  .flow-step,
  .record-item {
    transition: none;
  }
}
</style>
