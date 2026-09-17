<script setup lang="ts">
/* global crypto, URL, window, document */
import { computed, onMounted, ref, shallowRef } from 'vue'
import {
  ArrowRight,
  CircleCheck,
  Download,
  Key,
  Lock,
  Refresh,
  WarningFilled,
} from '@element-plus/icons-vue'
import { useRoute } from 'vue-router'

import { extractDrop, getDropMetadata, type DropMetadata, type ExtractedDrop } from '@/api/drops'
import { ApiError, messageForApiError } from '@/api/errors'

type DropStatus = DropMetadata['status']

const route = useRoute()
const metadata = shallowRef<DropMetadata | null>(null)
const result = shallowRef<ExtractedDrop | null>(null)
const accessCode = ref('')
const accessPassword = ref('')
const isLoading = ref(true)
const isExtracting = ref(false)
const metadataError = ref('')
const extractError = ref('')
const code = computed(() => String(route.params.code ?? '').trim())
const isVerified = computed(
  () => result.value?.signature_valid === true && result.value?.certificate_valid === true,
)
const safeDownloadUrl = computed(() => {
  const value = result.value?.download_url
  if (!value) return null
  try {
    const url = new URL(value, window.location.origin)
    return ['http:', 'https:', 'blob:'].includes(url.protocol) ? url.href : null
  } catch {
    return null
  }
})

const statusCopy: Record<DropStatus, { label: string; detail: string; tone: string }> = {
  available: {
    label: '等待提取',
    detail: '密封信封存在，输入单独收到的提取码后开启。',
    tone: 'ready',
  },
  consumed: {
    label: '已经提取',
    detail: '这封密信已被消费，不能再次打开。',
    tone: 'closed',
  },
  expired: {
    label: '已经过期',
    detail: '有效期已结束，服务器不再提供密信内容。',
    tone: 'closed',
  },
  destroyed: {
    label: '已经销毁',
    detail: '密信内容已销毁，仅可能保留脱敏审计记录。',
    tone: 'closed',
  },
  cooling_down: {
    label: '安全冷却中',
    detail: '错误尝试过多，请等待服务端冷却结束后再试。',
    tone: 'warning',
  },
}

const currentStatus = computed(() =>
  metadata.value ? statusCopy[metadata.value.status] : statusCopy.available,
)

function formatExpiry(value: string | null, burnAfterRead: boolean): string {
  if (burnAfterRead) return '首次成功提取后销毁'
  if (!value) return '以后端策略为准'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '以后端策略为准' : date.toLocaleString('zh-CN')
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return '未提供'
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1024 / 1024).toFixed(1)} MiB`
}

function metadataFailure(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return '未找到这封密信。链接可能无效、已过期或已被销毁。'
  }
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function extractionFailure(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return '密信不存在或已经失效，请向发送者确认链接。'
  }
  if (error instanceof ApiError && error.status === 409) {
    return '密信状态已经变化，可能已被提取或销毁。请刷新状态。'
  }
  if (error instanceof ApiError && error.status === 429) {
    return '错误尝试过多，链接已进入安全冷却。请稍后再试。'
  }
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

async function loadMetadata(): Promise<void> {
  if (!code.value) {
    metadataError.value = '提取链接缺少密信编号。'
    isLoading.value = false
    return
  }
  isLoading.value = true
  metadataError.value = ''
  extractError.value = ''
  result.value = null
  try {
    metadata.value = await getDropMetadata(code.value)
  } catch (error) {
    metadata.value = null
    metadataError.value = metadataFailure(error)
  } finally {
    isLoading.value = false
  }
}

async function submit(): Promise<void> {
  if (!metadata.value || metadata.value.status !== 'available' || isExtracting.value) return
  const normalizedCode = accessCode.value.toUpperCase().trim()
  if (!/^[A-Z0-9-]{8,32}$/.test(normalizedCode)) {
    extractError.value = '请输入 8–32 位大写字母、数字或连字符组成的提取码。'
    return
  }

  const password = accessPassword.value || undefined
  if (metadata.value.requires_password && !password) {
    extractError.value = '该密信设置了附加提取口令，请输入口令。'
    return
  }

  const request = {
    access_code: normalizedCode,
    ...(password ? { access_password: password } : {}),
  }

  // 提取码和附加口令属于敏感字段：组装请求后立即清空，不写入日志或持久化存储。
  accessCode.value = ''
  accessPassword.value = ''
  isExtracting.value = true
  extractError.value = ''
  result.value = null
  try {
    result.value = await extractDrop(code.value, request, crypto.randomUUID())
    if (isVerified.value && metadata.value.burn_after_read) {
      metadata.value = { ...metadata.value, status: 'consumed' }
    }
    if (result.value.kind === 'file' && isVerified.value && safeDownloadUrl.value && typeof document !== 'undefined') {
      const a = document.createElement('a')
      a.href = safeDownloadUrl.value
      a.download = metadata.value.filename || result.value.filename || 'download'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    }
  } catch (error) {
    extractError.value = extractionFailure(error)
  } finally {
    isExtracting.value = false
  }
}

onMounted(loadMetadata)
</script>

<template>
  <main id="main-content" class="extract-page">
    <div class="public-bar" aria-label="密信校园公共提取页">
      <RouterLink to="/login" class="brand" aria-label="返回密信校园登录页">
        <span class="brand-mark"
          ><el-icon><Lock /></el-icon
        ></span>
        <span><strong>密信校园</strong><small>CryptoCampus</small></span>
      </RouterLink>
      <span class="public-note"
        ><el-icon><Lock /></el-icon>无需登录 · 链接与提取码分离验证</span
      >
    </div>

    <section class="extract-shell" aria-labelledby="extract-title">
      <header class="hero">
        <div>
          <p class="eyebrow">提取密信 · 一次性数字信封 · FR-04</p>
          <h1 id="extract-title">有人给你发来一封密信</h1>
          <p>服务器先核验信封状态；只有提取请求通过后，页面才会展示后端返回的内容。</p>
        </div>
        <div class="envelope-seal" aria-hidden="true">
          <span></span><el-icon><Lock /></el-icon><span></span>
        </div>
      </header>

      <el-skeleton v-if="isLoading" class="loading-card" :rows="6" animated />

      <section v-else-if="metadataError" class="state-card error-state" role="alert">
        <el-icon><WarningFilled /></el-icon>
        <div>
          <strong>无法读取密信状态</strong>
          <p>{{ metadataError }}</p>
        </div>
        <el-button :icon="Refresh" @click="loadMetadata">重新检查</el-button>
      </section>

      <div v-else-if="metadata" class="extract-grid">
        <section class="ticket-card" aria-labelledby="ticket-title">
          <div class="card-kicker">
            <span>密封信封</span>
            <span class="status-chip" :class="currentStatus.tone" role="status">{{
              currentStatus.label
            }}</span>
          </div>
          <h2 id="ticket-title">
            {{ metadata.status === 'available' ? '输入另一渠道收到的提取信息' : '密信当前状态' }}
          </h2>
          <p class="status-detail">{{ currentStatus.detail }}</p>

          <dl class="metadata-list">
            <div>
              <dt>内容类型</dt>
              <dd>{{ metadata.kind === 'file' ? '文件密信' : '文字密信' }}</dd>
            </div>
            <div>
              <dt>密信编号</dt>
              <dd class="mono">{{ metadata.code }}</dd>
            </div>
            <div v-if="metadata.filename">
              <dt>文件名称</dt>
              <dd>{{ metadata.filename }}</dd>
            </div>
            <div v-if="metadata.kind === 'file'">
              <dt>文件大小</dt>
              <dd>{{ formatBytes(metadata.size) }}</dd>
            </div>
            <div>
              <dt>有效策略</dt>
              <dd>{{ formatExpiry(metadata.expires_at, metadata.burn_after_read) }}</dd>
            </div>
            <div>
              <dt>附加口令</dt>
              <dd>{{ metadata.requires_password ? '需要' : '不需要' }}</dd>
            </div>
          </dl>

          <form novalidate @submit.prevent="submit">
            <label for="extract-code">提取码</label>
            <el-input
              id="extract-code"
              v-model="accessCode"
              autocomplete="one-time-code"
              inputmode="text"
              maxlength="32"
              placeholder="例如 7H4K-92DM"
              :disabled="metadata.status !== 'available' || isExtracting"
              @input="accessCode = accessCode.toUpperCase()"
            />
            <small>提取码应通过与链接不同的渠道获得。</small>

            <template v-if="metadata.requires_password">
              <label for="extract-password">附加提取口令</label>
              <el-input
                id="extract-password"
                v-model="accessPassword"
                type="password"
                autocomplete="off"
                show-password
                maxlength="128"
                :disabled="metadata.status !== 'available' || isExtracting"
              />
            </template>

            <el-alert
              v-if="extractError"
              :title="extractError"
              type="warning"
              :closable="false"
              show-icon
            />
            <el-button
              native-type="submit"
              type="primary"
              size="large"
              :loading="isExtracting"
              :disabled="metadata.status !== 'available'"
              data-testid="extract-submit"
            >
              验证并开启密信
              <el-icon class="el-icon--right"><ArrowRight /></el-icon>
            </el-button>
          </form>
        </section>

        <section class="verification-card" aria-labelledby="verification-title">
          <template v-if="result">
            <div class="card-kicker"><span>后端验证回执</span><span>不展示密码中间值</span></div>
            <div v-if="isVerified" class="result-heading success">
              <el-icon><CircleCheck /></el-icon>
              <div>
                <h2 id="verification-title">身份校验通过</h2>
                <p>以下内容来自本次提取接口响应。</p>
              </div>
            </div>
            <div v-else class="result-heading blocked" role="alert">
              <el-icon><WarningFilled /></el-icon>
              <div>
                <h2 id="verification-title">内容已停止展示</h2>
                <p>签名或证书校验未通过，不展示返回内容。</p>
              </div>
            </div>

            <div class="verification-list" aria-label="后端返回的验证状态">
              <div :class="{ failed: !result.signature_valid }">
                <el-icon
                  ><component :is="result.signature_valid ? CircleCheck : WarningFilled"
                /></el-icon>
                <span
                  ><strong>发送者签名</strong
                  ><small>{{
                    result.signature_valid ? '后端返回有效' : '后端返回无效'
                  }}</small></span
                >
              </div>
              <div :class="{ failed: !result.certificate_valid }">
                <el-icon
                  ><component :is="result.certificate_valid ? CircleCheck : WarningFilled"
                /></el-icon>
                <span
                  ><strong>发送者证书</strong
                  ><small>{{
                    result.certificate_valid ? '后端返回有效' : '后端返回无效'
                  }}</small></span
                >
              </div>
              <div class="contract-note">
                <el-icon><Key /></el-icon>
                <span
                  ><strong>完整性与解封装</strong
                  ><small>由服务端处理，当前契约未返回独立结果字段</small></span
                >
              </div>
            </div>

            <template v-if="isVerified">
              <div v-if="result.kind === 'text' && result.content" class="content-panel">
                <span>密信内容</span>
                <pre>{{ result.content }}</pre>
              </div>
              <a
                v-else-if="result.kind === 'file' && safeDownloadUrl"
                class="download-link"
                :href="safeDownloadUrl"
                :download="metadata.filename || result.filename || 'download'"
                rel="noopener noreferrer"
              >
                <el-icon><Download /></el-icon
                ><span><strong>下载一次性文件</strong><small>如果浏览器未自动下载，可点击此处下载</small></span>
              </a>
              <el-alert
                v-else
                title="接口未返回可展示的内容或安全下载地址。"
                type="warning"
                :closable="false"
                show-icon
              />

              <div v-if="metadata.burn_after_read" class="burn-notice">
                <strong>阅后即焚</strong>
                <span>本次成功提取后不能重放；页面不会缓存密信内容。</span>
              </div>
              <RouterLink class="inspect-link" :to="`/inspect/records/${result.inspect_record_id}`">
                查看本次密码透视<el-icon><ArrowRight /></el-icon>
              </RouterLink>
            </template>
          </template>

          <template v-else>
            <div class="card-kicker"><span>安全开启顺序</span><span>服务端执行</span></div>
            <h2 id="verification-title">每一道校验都是一道门</h2>
            <ol class="verification-path">
              <li>
                <span>01</span>
                <div><strong>检查信封完整性</strong><small>篡改时立即终止，不返回明文</small></div>
              </li>
              <li>
                <span>02</span>
                <div>
                  <strong>验证证书与签名</strong><small>只接受后端明确确认的发送者状态</small>
                </div>
              </li>
              <li>
                <span>03</span>
                <div>
                  <strong>解封装并交付</strong><small>会话密钥和密码中间值不会进入页面</small>
                </div>
              </li>
              <li>
                <span>04</span>
                <div><strong>执行一次性策略</strong><small>阅后即焚密信不能再次提取</small></div>
              </li>
            </ol>
            <div class="privacy-note">
              <el-icon><Key /></el-icon>
              <p>页面不保存提取码、附加口令、私钥或会话密钥。</p>
            </div>
          </template>
        </section>
      </div>
    </section>
  </main>
</template>

<style scoped>
.extract-page {
  min-height: 100vh;
  padding: 0 32px 40px;
  background:
    linear-gradient(120deg, rgb(18 63 125 / 8%) 0 1px, transparent 1px 84px),
    radial-gradient(circle at 14% 8%, #dbeafd 0, transparent 28%), var(--cc-bg);
}
.public-bar {
  display: flex;
  width: min(1120px, 100%);
  min-height: 70px;
  margin: 0 auto;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid rgb(18 63 125 / 16%);
}
.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  color: var(--cc-primary-dark);
  text-decoration: none;
}
.brand-mark {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border-radius: 10px;
  color: #fff;
  background: var(--cc-primary-dark);
}
.brand strong,
.brand small {
  display: block;
}
.brand strong {
  font-size: 16px;
}
.brand small {
  margin-top: 1px;
  color: var(--cc-muted);
  font-size: 9px;
  letter-spacing: 0.04em;
}
.public-note {
  display: flex;
  align-items: center;
  gap: 7px;
  color: #3c5b49;
  font-size: 12px;
}
.extract-shell {
  width: min(1120px, 100%);
  margin: 0 auto;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 230px;
  gap: 40px;
  align-items: center;
  padding: 34px 0 25px;
}
.eyebrow,
.card-kicker {
  color: var(--cc-primary);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.hero h1 {
  margin: 6px 0 8px;
  color: var(--cc-primary-dark);
  font-size: clamp(30px, 4vw, 44px);
  line-height: 1.12;
}
.hero p:not(.eyebrow) {
  max-width: 680px;
  margin: 0;
  color: var(--cc-muted);
  font-size: 13px;
  line-height: 1.7;
}
.envelope-seal {
  display: grid;
  grid-template-columns: 1fr 48px 1fr;
  align-items: center;
  color: var(--cc-primary-dark);
}
.envelope-seal span {
  height: 1px;
  background: #9ebce2;
}
.envelope-seal .el-icon {
  display: grid;
  width: 48px;
  height: 48px;
  place-items: center;
  border: 1px solid #9ebce2;
  border-radius: 50%;
  background: #fff;
  font-size: 20px;
  box-shadow: 0 8px 20px rgb(18 63 125 / 10%);
}
.loading-card,
.state-card {
  padding: 32px;
  border: 1px solid var(--cc-line);
  border-radius: 16px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.state-card {
  display: flex;
  align-items: center;
  gap: 16px;
}
.state-card > .el-icon {
  color: var(--cc-danger);
  font-size: 28px;
}
.state-card div {
  flex: 1;
}
.state-card strong {
  color: var(--cc-primary-dark);
}
.state-card p {
  margin: 5px 0 0;
  color: var(--cc-muted);
  font-size: 12px;
}
.extract-grid {
  display: grid;
  grid-template-columns: minmax(0, 0.92fr) minmax(0, 1.08fr);
  gap: 18px;
}
.ticket-card,
.verification-card {
  min-height: 540px;
  padding: 26px;
  border: 1px solid var(--cc-line);
  border-radius: 16px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.ticket-card {
  position: relative;
  overflow: hidden;
}
.ticket-card::after {
  position: absolute;
  top: 0;
  right: -1px;
  width: 9px;
  height: 100%;
  background: radial-gradient(circle at 9px 9px, transparent 6px, var(--cc-bg) 6.5px) 0 0 / 9px 18px;
  content: '';
}
.card-kicker {
  display: flex;
  min-height: 24px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.card-kicker > span:last-child {
  color: var(--cc-muted);
  font-weight: 650;
  letter-spacing: 0;
  text-transform: none;
}
h2 {
  margin: 9px 0 7px;
  color: var(--cc-primary-dark);
  font-size: 20px;
}
.status-detail {
  min-height: 38px;
  margin: 0;
  color: var(--cc-muted);
  font-size: 12px;
  line-height: 1.6;
}
.status-chip {
  padding: 4px 9px;
  border-radius: 999px;
  font-size: 10px;
  letter-spacing: 0;
}
.status-chip.ready {
  color: var(--cc-success);
  background: #e8f6ee;
}
.status-chip.warning {
  color: #8a5a00;
  background: #fff4d7;
}
.status-chip.closed {
  color: var(--cc-danger);
  background: #fdecea;
}
.metadata-list {
  display: grid;
  margin: 15px 0 18px;
  border-top: 1px solid #edf0f4;
}
.metadata-list div {
  display: grid;
  grid-template-columns: 96px minmax(0, 1fr);
  gap: 16px;
  padding: 8px 0;
  border-bottom: 1px solid #edf0f4;
  font-size: 11px;
}
.metadata-list dt {
  color: var(--cc-muted);
}
.metadata-list dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: #314158;
  font-weight: 700;
  text-align: right;
}
.mono {
  font-family: 'Cascadia Code', Consolas, monospace;
}
form {
  display: grid;
  gap: 8px;
}
form label {
  color: #354256;
  font-size: 12px;
  font-weight: 750;
}
form small {
  color: var(--cc-muted);
  font-size: 10px;
}
form .el-button {
  width: 100%;
  margin-top: 8px;
}
.verification-card {
  display: flex;
  flex-direction: column;
}
.result-heading {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 12px 0 18px;
  padding: 14px;
  border-radius: 10px;
}
.result-heading > .el-icon {
  font-size: 30px;
}
.result-heading h2 {
  margin: 0;
}
.result-heading p {
  margin: 3px 0 0;
  color: var(--cc-muted);
  font-size: 10px;
}
.result-heading.success {
  color: var(--cc-success);
  background: #eaf7ef;
}
.result-heading.blocked {
  color: var(--cc-danger);
  background: #fdecea;
}
.verification-list {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 9px;
}
.verification-list > div {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 11px;
  border: 1px solid #cfe5d8;
  border-radius: 9px;
  color: var(--cc-success);
  background: #f5fbf7;
}
.verification-list > div.failed {
  border-color: #efcbc7;
  color: var(--cc-danger);
  background: #fff7f6;
}
.verification-list > div.contract-note {
  grid-column: 1 / -1;
  border-color: #d7e2f1;
  color: var(--cc-primary);
  background: #f6f9fd;
}
.verification-list span,
.verification-list strong,
.verification-list small {
  display: block;
}
.verification-list small {
  margin-top: 2px;
  color: var(--cc-muted);
  font-size: 9px;
}
.content-panel {
  margin-top: 14px;
}
.content-panel > span {
  color: var(--cc-muted);
  font-size: 10px;
  font-weight: 700;
}
.content-panel pre {
  max-height: 188px;
  margin: 7px 0 0;
  overflow: auto;
  padding: 15px;
  border: 1px solid #d9e5df;
  border-radius: 10px;
  color: #20382a;
  background: #f4faf6;
  font-family: inherit;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.download-link {
  display: flex;
  align-items: center;
  gap: 11px;
  margin-top: 14px;
  padding: 16px;
  border: 1px solid #bfd5f1;
  border-radius: 10px;
  color: var(--cc-primary);
  background: var(--cc-primary-light);
  text-decoration: none;
}
.download-link > .el-icon {
  font-size: 24px;
}
.download-link strong,
.download-link small {
  display: block;
}
.download-link small {
  margin-top: 3px;
  color: var(--cc-muted);
  font-size: 10px;
}
.burn-notice {
  display: grid;
  gap: 3px;
  margin-top: 13px;
  padding: 11px 13px;
  border-left: 3px solid var(--cc-danger);
  color: #6b302c;
  background: #fff5f4;
  font-size: 10px;
}
.inspect-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: auto;
  padding-top: 16px;
  color: var(--cc-primary);
  font-size: 12px;
  font-weight: 750;
  text-decoration: none;
}
.verification-path {
  display: grid;
  gap: 8px;
  margin: 20px 0;
  padding: 0;
  list-style: none;
}
.verification-path li {
  display: flex;
  align-items: center;
  gap: 13px;
  padding: 11px 12px;
  border: 1px solid #edf0f4;
  border-radius: 9px;
  background: #f8fafc;
}
.verification-path li > span {
  color: #78a2d6;
  font:
    700 11px/1 'Cascadia Code',
    Consolas,
    monospace;
}
.verification-path strong,
.verification-path small {
  display: block;
}
.verification-path strong {
  color: #314158;
  font-size: 12px;
}
.verification-path small {
  margin-top: 3px;
  color: var(--cc-muted);
  font-size: 9px;
}
.privacy-note {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: auto;
  padding: 13px;
  border-top: 1px solid #dbe4ef;
  color: var(--cc-primary-dark);
}
.privacy-note p {
  margin: 0;
  font-size: 11px;
}
@media (max-width: 800px) {
  .extract-page {
    padding: 0 16px 28px;
  }
  .public-note {
    display: none;
  }
  .hero {
    grid-template-columns: 1fr;
    padding-top: 26px;
  }
  .envelope-seal {
    display: none;
  }
  .extract-grid {
    grid-template-columns: 1fr;
  }
  .ticket-card,
  .verification-card {
    min-height: auto;
  }
}
@media (max-width: 480px) {
  .ticket-card,
  .verification-card {
    padding: 20px;
  }
  .verification-list {
    grid-template-columns: 1fr;
  }
  .verification-list > div.contract-note {
    grid-column: auto;
  }
  .state-card {
    align-items: flex-start;
    flex-wrap: wrap;
  }
}
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    scroll-behavior: auto !important;
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
  }
}
</style>
