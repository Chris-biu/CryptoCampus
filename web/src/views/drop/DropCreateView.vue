<script setup lang="ts">
/* global DragEvent, Event, File, HTMLInputElement, URL, crypto, navigator, window */
import { computed, ref, shallowRef } from 'vue'
import { Check, CopyDocument, Document, Key, Lock, UploadFilled } from '@element-plus/icons-vue'

import {
  createFileDrop,
  createTextDrop,
  type CreateDropResponse,
  type TtlPolicy,
} from '@/api/drops'
import { ApiError, messageForApiError } from '@/api/errors'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

type DropKind = 'text' | 'file'

const MAX_TEXT_LENGTH = 1_048_576
const MAX_FILE_BYTES = 100 * 1024 * 1024
const MAX_PASSWORD_LENGTH = 128

const ttlOptions: ReadonlyArray<{ label: string; hint: string; value: TtlPolicy }> = [
  { label: '阅后即焚', hint: '首次成功提取后销毁', value: 'burn_after_read' },
  { label: '24 小时', hint: '到期后自动销毁', value: 'hours_24' },
  { label: '7 天', hint: '适合短期协作', value: 'days_7' },
]

const session = useSessionStore()
const security = useSecurityStore()
const dropKind = ref<DropKind>('text')
const content = ref('')
const selectedFile = shallowRef<File | null>(null)
const ttlPolicy = ref<TtlPolicy>('burn_after_read')
const accessPassword = ref('')
const isSubmitting = ref(false)
const isDragging = ref(false)
const formError = ref('')
const requestError = ref('')
const copyFeedback = ref('')
const result = shallowRef<CreateDropResponse | null>(null)

const pqcEnabled = computed(() => security.pqcEnabled ?? session.currentUser?.pqc_mode ?? false)
const modeLabel = computed(() =>
  pqcEnabled.value ? 'SM2 + ML-KEM 混合信封' : 'SM4-GCM + SM2 数字信封',
)
const selectedTtl = computed(
  () => ttlOptions.find((option) => option.value === ttlPolicy.value) ?? ttlOptions[0],
)
const resultUrl = computed(() => {
  if (!result.value) return ''
  return new URL(result.value.url, window.location.origin).href
})

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

function formatExpiry(value: string | null): string {
  if (!value) return '首次成功提取后销毁'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '以后端返回时间为准'
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function chooseKind(kind: DropKind): void {
  if (isSubmitting.value) return
  dropKind.value = kind
  formError.value = ''
  requestError.value = ''
  result.value = null
}

function validateFile(file: File): boolean {
  if (file.size === 0) {
    formError.value = '不能上传空文件。'
    return false
  }
  if (file.size > MAX_FILE_BYTES) {
    formError.value = '文件不能超过 100 MiB。'
    return false
  }
  formError.value = ''
  selectedFile.value = file
  result.value = null
  return true
}

function onFileChange(event: Event): void {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) validateFile(file)
  input.value = ''
}

function onFileDrop(event: DragEvent): void {
  isDragging.value = false
  const file = event.dataTransfer?.files[0]
  if (file) validateFile(file)
}

function removeFile(): void {
  if (isSubmitting.value) return
  selectedFile.value = null
  formError.value = ''
  result.value = null
}

function validate(): boolean {
  if (accessPassword.value.length > MAX_PASSWORD_LENGTH) {
    formError.value = '附加提取口令不能超过 128 位。'
    return false
  }
  if (dropKind.value === 'text') {
    if (!content.value.trim()) {
      formError.value = '请输入要分享的文字内容。'
      return false
    }
    if (content.value.length > MAX_TEXT_LENGTH) {
      formError.value = '文字内容不能超过 1 MiB。'
      return false
    }
  } else if (!selectedFile.value) {
    if (!formError.value) formError.value = '请选择一个不超过 100 MiB 的文件。'
    return false
  }
  formError.value = ''
  return true
}

function createIdempotencyKey(): string {
  return crypto.randomUUID()
}

async function submitDrop(): Promise<void> {
  if (isSubmitting.value || !validate()) return
  if (!session.accessToken) {
    requestError.value = '登录状态已失效，请重新登录。'
    return
  }

  isSubmitting.value = true
  requestError.value = ''
  copyFeedback.value = ''
  result.value = null
  const password = accessPassword.value || undefined
  accessPassword.value = ''

  try {
    const idempotencyKey = createIdempotencyKey()
    result.value =
      dropKind.value === 'text'
        ? await createTextDrop(
            {
              content: content.value,
              ttl_policy: ttlPolicy.value,
              pqc_mode: pqcEnabled.value,
              ...(password ? { access_password: password } : {}),
            },
            session.accessToken,
            idempotencyKey,
          )
        : await createFileDrop(
            {
              file: selectedFile.value as File,
              ttl_policy: ttlPolicy.value,
              pqc_mode: pqcEnabled.value,
              ...(password ? { access_password: password } : {}),
            },
            session.accessToken,
            idempotencyKey,
          )
  } catch (error) {
    requestError.value =
      error instanceof ApiError
        ? messageForApiError(error.code, error.status)
        : messageForApiError('UNKNOWN_ERROR')
  } finally {
    isSubmitting.value = false
  }
}

async function copyValue(value: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value)
    copyFeedback.value = `${label}已复制。`
  } catch {
    copyFeedback.value = `无法自动复制${label}，请手动选择复制。`
  }
}
</script>

<template>
  <section class="drop-create" aria-labelledby="drop-create-title">
    <header class="drop-heading">
      <div>
        <p class="eyebrow">一次性安全分享</p>
        <h1 id="drop-create-title">密信快传 · 创建</h1>
        <p>提交文字或文件，由后端 openHiTLS 密码引擎生成数字信封。</p>
      </div>
      <el-tag :type="pqcEnabled ? 'warning' : 'primary'" effect="plain" round>
        {{ modeLabel }}
      </el-tag>
    </header>

    <div class="drop-layout">
      <section class="drop-card composer-card" aria-labelledby="drop-content-title">
        <div class="section-title">
          <span>01</span>
          <div>
            <h2 id="drop-content-title">要分享的内容</h2>
            <p>前端只提交业务数据，不执行或模拟密码算法。</p>
          </div>
        </div>

        <div class="kind-switch" role="group" aria-label="密信类型">
          <button
            type="button"
            :class="{ active: dropKind === 'text' }"
            :aria-pressed="dropKind === 'text'"
            @click="chooseKind('text')"
          >
            <el-icon><Document /></el-icon>
            文字便签
          </button>
          <button
            type="button"
            :class="{ active: dropKind === 'file' }"
            :aria-pressed="dropKind === 'file'"
            @click="chooseKind('file')"
          >
            <el-icon><UploadFilled /></el-icon>
            文件上传
          </button>
        </div>

        <div v-if="dropKind === 'text'" class="field-block">
          <label for="drop-content">文字内容</label>
          <el-input
            id="drop-content"
            v-model="content"
            data-testid="drop-content"
            type="textarea"
            :rows="5"
            resize="none"
            :maxlength="MAX_TEXT_LENGTH"
            placeholder="输入需要安全分享的便签内容"
            @input="result = null"
          />
          <small>{{ content.length.toLocaleString('zh-CN') }} / 1,048,576 字符</small>
        </div>

        <div v-else class="field-block">
          <label>文件</label>
          <label
            class="file-dropzone"
            :class="{ dragging: isDragging, selected: selectedFile }"
            @dragenter.prevent="isDragging = true"
            @dragover.prevent="isDragging = true"
            @dragleave.prevent="isDragging = false"
            @drop.prevent="onFileDrop"
          >
            <input
              data-testid="drop-file"
              type="file"
              :disabled="isSubmitting"
              @change="onFileChange"
            />
            <el-icon><component :is="selectedFile ? Check : UploadFilled" /></el-icon>
            <strong>{{ selectedFile ? selectedFile.name : '拖入文件，或点击选择' }}</strong>
            <span>{{
              selectedFile ? formatBytes(selectedFile.size) : '单个文件，最大 100 MiB'
            }}</span>
          </label>
          <button v-if="selectedFile" class="remove-file" type="button" @click="removeFile">
            移除文件
          </button>
        </div>

        <div class="form-grid">
          <div class="field-block">
            <label for="drop-password">附加提取口令（可选）</label>
            <el-input
              id="drop-password"
              v-model="accessPassword"
              data-testid="drop-password"
              type="password"
              show-password
              :maxlength="MAX_PASSWORD_LENGTH"
              autocomplete="new-password"
              placeholder="与分享链接分开传递"
            >
              <template #prefix
                ><el-icon><Key /></el-icon
              ></template>
            </el-input>
          </div>
          <div class="field-block">
            <label for="drop-ttl">有效期</label>
            <el-select id="drop-ttl" v-model="ttlPolicy" data-testid="drop-ttl">
              <el-option
                v-for="option in ttlOptions"
                :key="option.value"
                :label="option.label"
                :value="option.value"
              />
            </el-select>
            <small>{{ selectedTtl.hint }}</small>
          </div>
        </div>

        <el-alert
          v-if="formError"
          class="form-alert"
          :title="formError"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-alert
          v-if="requestError"
          class="form-alert"
          :title="requestError"
          type="error"
          :closable="false"
          show-icon
        />

        <el-button
          class="create-button"
          data-testid="create-drop"
          type="primary"
          size="large"
          :icon="Lock"
          :loading="isSubmitting"
          @click="submitDrop"
        >
          {{ isSubmitting ? '正在生成安全信封' : '生成密信' }}
        </el-button>
      </section>

      <div class="result-column">
        <section class="drop-card result-card" aria-labelledby="drop-result-title">
          <div class="section-title">
            <span>02</span>
            <div>
              <h2 id="drop-result-title">分享结果</h2>
              <p>链接与提取码应通过不同渠道发送。</p>
            </div>
          </div>

          <div v-if="result" class="result-content" aria-live="polite">
            <div class="result-row">
              <span>分享链接</span>
              <code data-testid="result-url">{{ resultUrl }}</code>
              <el-button :icon="CopyDocument" @click="copyValue(resultUrl, '分享链接')">
                复制链接
              </el-button>
            </div>
            <div class="result-row access-code-row">
              <span>提取码</span>
              <strong data-testid="result-code">{{ result.access_code }}</strong>
              <el-button :icon="CopyDocument" @click="copyValue(result.access_code, '提取码')">
                复制提取码
              </el-button>
            </div>
            <div class="result-meta">
              <span>销毁时间</span>
              <strong>{{ formatExpiry(result.expires_at) }}</strong>
              <span>信封模式</span>
              <strong>{{ result.pqc_mode ? '抗量子混合模式' : '国密基线模式' }}</strong>
            </div>
            <p v-if="copyFeedback" class="copy-feedback" role="status">{{ copyFeedback }}</p>
            <el-alert
              title="请勿在同一条消息中同时发送链接、提取码和附加口令。"
              type="success"
              :closable="false"
              show-icon
            />
          </div>
          <div v-else class="result-empty">
            <el-icon><Lock /></el-icon>
            <strong>尚未生成密信</strong>
            <span>完成左侧内容设置后，安全分享信息会显示在这里。</span>
          </div>
        </section>

        <section class="drop-card envelope-card" aria-labelledby="envelope-title">
          <div class="section-title compact">
            <span>03</span>
            <div>
              <h2 id="envelope-title">数字信封流程</h2>
              <p>仅展示算法职责，不展示密钥或明文。</p>
            </div>
          </div>
          <ol class="envelope-flow">
            <li>
              <span>1</span>
              <div><strong>内容加密</strong><small>随机会话密钥 · SM4-GCM</small></div>
            </li>
            <li>
              <span>2</span>
              <div>
                <strong>密钥封装</strong>
                <small>{{ pqcEnabled ? 'SM2 + ML-KEM 双重封装' : 'SM2 公钥封装' }}</small>
              </div>
            </li>
            <li>
              <span>3</span>
              <div><strong>来源签名</strong><small>发送者证书 · SM3-with-SM2</small></div>
            </li>
          </ol>
        </section>
      </div>
    </div>
  </section>
</template>

<style scoped>
.drop-create {
  display: grid;
  gap: 22px;
}

.drop-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
}

.drop-heading h1 {
  margin: 4px 0 7px;
  color: var(--cc-primary-dark);
  font-size: clamp(26px, 3vw, 34px);
  line-height: 1.2;
}

.drop-heading p:not(.eyebrow) {
  margin: 0;
  color: var(--cc-muted);
  font-size: 13px;
}

.drop-heading > .el-tag {
  margin-top: 8px;
  padding-inline: 13px;
}

.drop-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(360px, 0.92fr);
  gap: 18px;
  align-items: start;
}

.drop-card {
  min-width: 0;
  padding: 22px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: var(--cc-card);
  box-shadow: var(--cc-shadow);
}

.composer-card {
  min-height: 590px;
}

.result-column {
  display: grid;
  gap: 18px;
}

.section-title {
  display: flex;
  align-items: flex-start;
  gap: 11px;
  margin-bottom: 18px;
}

.section-title > span {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 9px;
  color: var(--cc-primary);
  background: var(--cc-primary-light);
  font-size: 11px;
  font-weight: 800;
}

.section-title h2 {
  margin: 0 0 3px;
  color: var(--cc-primary-dark);
  font-size: 18px;
}

.section-title p {
  margin: 0;
  color: var(--cc-muted);
  font-size: 11px;
  line-height: 1.5;
}

.section-title.compact {
  margin-bottom: 14px;
}

.kind-switch {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  margin-bottom: 18px;
  padding: 4px;
  border: 1px solid var(--cc-line);
  border-radius: 10px;
  background: #f3f6fa;
}

.kind-switch button {
  display: flex;
  min-height: 40px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  border: 0;
  border-radius: 7px;
  color: var(--cc-muted);
  background: transparent;
  cursor: pointer;
  font-size: 13px;
  font-weight: 700;
  transition:
    color 160ms ease,
    background-color 160ms ease,
    box-shadow 160ms ease;
}

.kind-switch button:hover,
.kind-switch button.active {
  color: var(--cc-primary-dark);
  background: #fff;
}

.kind-switch button.active {
  box-shadow: 0 3px 10px rgb(18 63 125 / 10%);
}

.field-block {
  position: relative;
  display: grid;
  gap: 7px;
}

.field-block label {
  color: #354256;
  font-size: 12px;
  font-weight: 700;
}

.field-block small {
  color: var(--cc-muted);
  font-size: 10px;
  text-align: right;
}

.form-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.18fr) minmax(170px, 0.82fr);
  gap: 13px;
  margin-top: 16px;
}

.field-block :deep(.el-input__wrapper),
.field-block :deep(.el-select__wrapper),
.field-block :deep(.el-textarea__inner) {
  border-radius: 8px;
  box-shadow: 0 0 0 1px var(--cc-line) inset;
}

.field-block :deep(.el-input__wrapper),
.field-block :deep(.el-select__wrapper) {
  min-height: 40px;
}

.field-block :deep(.el-textarea__inner) {
  min-height: 142px !important;
  padding: 12px;
  line-height: 1.65;
}

.file-dropzone {
  display: grid;
  min-height: 172px;
  place-items: center;
  align-content: center;
  gap: 7px;
  border: 1.5px dashed #a9bad0;
  border-radius: 10px;
  color: var(--cc-muted);
  background: #f8fafc;
  cursor: pointer;
  text-align: center;
  transition:
    border-color 160ms ease,
    background-color 160ms ease;
}

.file-dropzone:hover,
.file-dropzone.dragging {
  border-color: var(--cc-primary);
  background: var(--cc-primary-light);
}

.file-dropzone.selected {
  border-style: solid;
  border-color: #85b59c;
  background: #f1faf5;
}

.file-dropzone input {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}

.file-dropzone .el-icon {
  color: var(--cc-primary);
  font-size: 30px;
}

.file-dropzone strong {
  max-width: 90%;
  overflow: hidden;
  color: var(--cc-primary-dark);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-dropzone span {
  font-size: 11px;
}

.remove-file {
  position: absolute;
  right: 10px;
  bottom: 10px;
  border: 0;
  color: var(--cc-danger);
  background: transparent;
  cursor: pointer;
  font-size: 11px;
}

.form-alert {
  margin-top: 14px;
}

.create-button {
  width: 100%;
  min-height: 44px;
  margin-top: 17px;
  border-radius: 9px;
  font-weight: 750;
  letter-spacing: 0.04em;
}

.result-card {
  min-height: 350px;
}

.result-empty {
  display: grid;
  min-height: 245px;
  place-items: center;
  align-content: center;
  gap: 8px;
  color: var(--cc-muted);
  text-align: center;
}

.result-empty .el-icon {
  margin-bottom: 3px;
  color: #92a6bf;
  font-size: 34px;
}

.result-empty strong {
  color: #3c4c62;
  font-size: 14px;
}

.result-empty span {
  max-width: 270px;
  font-size: 11px;
  line-height: 1.6;
}

.result-content {
  display: grid;
  gap: 11px;
}

.result-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 7px 10px;
  align-items: center;
  padding: 12px;
  border: 1px solid #dce4ed;
  border-radius: 9px;
  background: #f7f9fc;
}

.result-row > span {
  grid-column: 1 / -1;
  color: var(--cc-muted);
  font-size: 10px;
  font-weight: 700;
}

.result-row code {
  overflow: hidden;
  color: #29486f;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.access-code-row strong {
  color: var(--cc-success);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 19px;
  letter-spacing: 0.12em;
}

.result-meta {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 6px 12px;
  padding: 2px 3px;
  font-size: 11px;
}

.result-meta span {
  color: var(--cc-muted);
}

.result-meta strong {
  color: #34465d;
  text-align: right;
}

.copy-feedback {
  margin: 0;
  color: var(--cc-success);
  font-size: 11px;
}

.envelope-card {
  padding-block: 18px;
}

.envelope-flow {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.envelope-flow li {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 7px;
  padding: 10px;
  border: 1px solid #e0e6ee;
  border-radius: 8px;
  background: #fafbfd;
}

.envelope-flow li > span {
  display: grid;
  width: 20px;
  height: 20px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 50%;
  color: #fff;
  background: var(--cc-primary);
  font-size: 10px;
  font-weight: 800;
}

.envelope-flow strong,
.envelope-flow small {
  display: block;
}

.envelope-flow strong {
  color: #34465d;
  font-size: 11px;
}

.envelope-flow small {
  margin-top: 4px;
  color: var(--cc-muted);
  font-size: 9px;
  line-height: 1.4;
}

@media (max-width: 1080px) {
  .drop-layout {
    grid-template-columns: 1fr;
  }

  .composer-card {
    min-height: auto;
  }
}

@media (max-width: 720px) {
  .drop-heading,
  .form-grid {
    grid-template-columns: 1fr;
    flex-direction: column;
  }

  .drop-heading > .el-tag {
    margin-top: 0;
  }

  .envelope-flow {
    grid-template-columns: 1fr;
  }
}
</style>
