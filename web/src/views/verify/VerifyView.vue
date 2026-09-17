<script setup lang="ts">
/* global Event, File, HTMLInputElement, crypto, document, URL */
import { computed, ref, shallowRef } from 'vue'
import { Check, CircleClose, DocumentChecked, Stamp, UploadFilled } from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import {
  createSeal,
  downloadSealSidecar,
  verifyFile,
  type Seal,
  type VerificationResult,
} from '@/api/verify'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const security = useSecurityStore()
const mode = ref<'seal' | 'verify'>('verify')
const sourceFile = shallowRef<File | null>(null)
const sealFile = shallowRef<File | null>(null)
const sealProfile = ref<'personal' | 'department' | 'academic'>('personal')
const outputFormat = ref<'sidecar' | 'qr' | 'pdf_signature_page'>('sidecar')
const createdSeal = shallowRef<Seal | null>(null)
const verification = shallowRef<VerificationResult | null>(null)
const loading = ref(false)
const downloading = ref(false)
const error = ref('')
const pqcMode = computed(() => security.pqcEnabled ?? session.currentUser?.pqc_mode ?? false)
const fileLimit = 100 * 1024 * 1024
const sidecarLimit = 128 * 1024
const formatHint = '仅支持 PDF、PNG 或 JPEG 文件，请转换格式后重试。'
let sourceSelection = 0

async function isSupportedSource(file: File): Promise<boolean> {
  if (!file.size || file.size > fileLimit) return false
  const header = new Uint8Array(await file.slice(0, 8).arrayBuffer())
  const pdf =
    header.length >= 5 && [37, 80, 68, 70, 45].every((byte, index) => header[index] === byte)
  const png =
    header.length >= 8 &&
    [137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => header[index] === byte)
  const jpeg = header.length >= 3 && [255, 216, 255].every((byte, index) => header[index] === byte)
  return (
    (pdf && (!file.type || file.type === 'application/pdf')) ||
    (png && (!file.type || file.type === 'image/png')) ||
    (jpeg && (!file.type || file.type === 'image/jpeg'))
  )
}

async function pick(event: Event, target: 'source' | 'seal'): Promise<void> {
  if (loading.value) return
  const input = event.target as HTMLInputElement
  const file = input.files?.[0] ?? null
  error.value = ''
  verification.value = null
  createdSeal.value = null
  if (target === 'source') {
    const selection = ++sourceSelection
    sourceFile.value = null
    if (!file) return
    try {
      if (file.size > fileLimit) error.value = '原文件不能超过 100 MiB。'
      else if (!(await isSupportedSource(file))) error.value = formatHint
      if (selection !== sourceSelection) return
      if (!error.value) sourceFile.value = file
    } catch {
      if (selection !== sourceSelection) return
      error.value = '无法读取文件，请重新选择。'
    }
    if (error.value) input.value = ''
  } else {
    sealFile.value = file && file.size <= sidecarLimit ? file : null
    if (file && file.size > sidecarLimit) {
      error.value = 'Sidecar 验真凭证不能超过 128 KiB。'
      input.value = ''
    }
  }
}
function setMode(value: 'seal' | 'verify'): void {
  if (loading.value) return
  mode.value = value
  error.value = ''
  if (value === 'verify') createdSeal.value = null
  else verification.value = null
}
async function submit(): Promise<void> {
  if (loading.value) return
  if (!sourceFile.value || (mode.value === 'verify' && !sealFile.value)) {
    error.value = mode.value === 'verify' ? '请选择原文件和验真凭证。' : '请选择需要签发的文件。'
    return
  }
  if (sourceFile.value.size > fileLimit) {
    error.value = '原文件不能超过 100 MiB。'
    return
  }
  if ((sealFile.value?.size ?? 0) > sidecarLimit) {
    error.value = 'Sidecar 验真凭证不能超过 128 KiB。'
    return
  }
  try {
    if (!(await isSupportedSource(sourceFile.value))) {
      error.value = formatHint
      return
    }
  } catch {
    error.value = '无法读取文件，请重新选择。'
    return
  }
  loading.value = true
  error.value = ''
  verification.value = null
  createdSeal.value = null
  try {
    if (mode.value === 'seal') {
      if (!session.accessToken) throw new ApiError({ code: 'UNAUTHORIZED', status: 401 })
      createdSeal.value = await createSeal(
        {
          file: sourceFile.value,
          sealProfile: sealProfile.value,
          pqcMode: pqcMode.value,
          outputFormat: outputFormat.value,
        },
        session.accessToken,
        crypto.randomUUID(),
      )
    } else verification.value = await verifyFile(sourceFile.value, sealFile.value as File)
  } catch (caught) {
    error.value =
      caught instanceof ApiError
        ? caught.status === 422 && mode.value === 'seal'
          ? '签发请求未被接受，请检查文件格式、签章口径与输出方式。'
          : messageForApiError(caught.code, caught.status)
        : messageForApiError('UNKNOWN_ERROR')
  } finally {
    loading.value = false
  }
}
async function downloadSeal(): Promise<void> {
  if (!createdSeal.value || downloading.value) return
  downloading.value = true
  error.value = ''
  try {
    const sidecar = await downloadSealSidecar(createdSeal.value.id)
    const url = URL.createObjectURL(sidecar)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `seal-${createdSeal.value.id}.ccseal`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch (caught) {
    error.value =
      caught instanceof ApiError
        ? messageForApiError(caught.code, caught.status)
        : messageForApiError('UNKNOWN_ERROR')
  } finally {
    downloading.value = false
  }
}
const stepLabels: Record<string, string> = {
  digest: '文件摘要',
  signature: '数字签名',
  certificate_chain: '证书链',
  timestamp: '签章时间',
  revocation: '吊销状态',
}
</script>

<template>
  <section class="verify-page" aria-labelledby="verify-title">
    <header>
      <div>
        <p class="eyebrow">五步验证 · 全部通过才判定有效</p>
        <h1 id="verify-title">文件验真中心</h1>
        <p>为校园证明签发电子凭证，或上传原文件与凭证进行公开验真。</p>
      </div>
      <el-tag :type="pqcMode ? 'warning' : 'primary'" effect="plain">{{
        pqcMode ? '已请求抗量子模式，能力由后端确认' : 'SM3-with-SM2'
      }}</el-tag>
    </header>
    <div class="mode-switch">
      <button
        type="button"
        :disabled="loading"
        :class="{ active: mode === 'verify' }"
        @click="setMode('verify')"
      >
        <el-icon><DocumentChecked /></el-icon>验证文件</button
      ><button
        type="button"
        :disabled="loading"
        :class="{ active: mode === 'seal' }"
        @click="setMode('seal')"
      >
        <el-icon><Stamp /></el-icon>签发凭证
      </button>
    </div>
    <div class="verify-layout">
      <section class="panel input-panel">
        <div class="panel-title">
          <span>01</span>
          <div>
            <h2>{{ mode === 'verify' ? '上传验真材料' : '设置签发材料' }}</h2>
            <p>文件内容仅用于当前请求，不写入浏览器存储</p>
          </div>
        </div>
        <label class="upload-box"
          ><input
            type="file"
            accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
            :disabled="loading"
            @change="pick($event, 'source')"
          /><el-icon><UploadFilled /></el-icon
          ><strong>{{ sourceFile?.name ?? '选择原始文件' }}</strong
          ><span>{{ sourceFile ? '已就绪' : 'PDF、PNG、JPEG，最大 100 MiB' }}</span></label
        ><label v-if="mode === 'verify'" class="upload-box compact"
          ><input
            type="file"
            accept=".ccseal,.json,application/json,application/octet-stream"
            :disabled="loading"
            @change="pick($event, 'seal')"
          /><el-icon><DocumentChecked /></el-icon
          ><strong>{{ sealFile?.name ?? '选择验真凭证' }}</strong
          ><span>Sidecar 或平台签章文件</span></label
        ><template v-else
          ><div class="settings">
            <label
              >签章口径<el-select v-model="sealProfile" :disabled="loading"
                ><el-option label="个人签章" value="personal" /><el-option
                  label="部门签章"
                  value="department" /><el-option
                  label="教务口径章"
                  value="academic" /></el-select></label
            ><label
              >输出方式<el-select v-model="outputFormat" :disabled="loading"
                ><el-option label="Sidecar 凭证" value="sidecar" /><el-option
                  label="验真二维码（待输出协议支持）"
                  disabled
                  value="qr" /><el-option
                  label="PDF 附加签章页（待输出协议支持）"
                  disabled
                  value="pdf_signature_page" /></el-select
            ></label></div></template
        ><el-alert
          v-if="error"
          :title="error"
          type="warning"
          :closable="false"
          show-icon
        /><el-button type="primary" size="large" :loading="loading" @click="submit">{{
          mode === 'verify' ? '开始五步验真' : '盖章并生成凭证'
        }}</el-button>
      </section>
      <section class="panel result-panel">
        <div class="panel-title">
          <span>02</span>
          <div>
            <h2>{{ mode === 'verify' ? '验真结论' : '签发结果' }}</h2>
            <p>所有结论以后端密码引擎结果为准</p>
          </div>
        </div>
        <template v-if="verification"
          ><div class="verdict" :class="{ valid: verification.valid }">
            <el-icon><component :is="verification.valid ? Check : CircleClose" /></el-icon>
            <div>
              <strong>{{ verification.valid ? '文件真实且完整' : '验真未通过' }}</strong
              ><span>{{
                verification.valid ? '五项检查全部通过' : '请勿信任或继续传播此文件'
              }}</span>
            </div>
          </div>
          <ol class="steps">
            <li
              v-for="step in verification.steps"
              :key="step.name"
              :class="{ passed: step.passed }"
            >
              <el-icon><component :is="step.passed ? Check : CircleClose" /></el-icon>
              <div>
                <strong>{{ stepLabels[step.name] ?? step.name }}</strong
                ><span>{{ step.message }}</span>
              </div>
            </li>
          </ol>
          <code>记录摘要 {{ verification.record_digest }}</code></template
        ><template v-else-if="createdSeal"
          ><div class="verdict valid">
            <el-icon><Check /></el-icon>
            <div>
              <strong>签发完成</strong><span>{{ createdSeal.signature_algorithm }}</span>
            </div>
          </div>
          <dl>
            <div>
              <dt>摘要算法</dt>
              <dd>{{ createdSeal.digest_algorithm }}</dd>
            </div>
            <div>
              <dt>签发时间</dt>
              <dd>{{ new Date(createdSeal.timestamp).toLocaleString('zh-CN') }}</dd>
            </div>
            <div>
              <dt>凭证编号</dt>
              <dd>{{ createdSeal.id }}</dd>
            </div>
          </dl>
          <el-button :loading="downloading" @click="downloadSeal">下载 Sidecar 验真凭证</el-button>
          <el-alert
            title="页面仅显示摘要元信息；私钥和完整签名材料不会写入日志。"
            type="success"
            :closable="false"
            show-icon
        /></template>
        <div v-else class="empty-result">
          <el-icon><DocumentChecked /></el-icon
          ><strong>等待{{ mode === 'verify' ? '验真' : '签发' }}</strong
          ><span>完成左侧材料选择后开始。</span>
        </div>
      </section>
    </div>
  </section>
</template>

<style scoped>
.verify-page {
  display: grid;
  gap: 20px;
}
.verify-page > header {
  display: flex;
  justify-content: space-between;
  gap: 20px;
}
.verify-page h1 {
  margin: 4px 0 7px;
  color: var(--cc-primary-dark);
  font-size: 32px;
}
.verify-page header p:not(.eyebrow) {
  margin: 0;
  color: var(--cc-muted);
  font-size: 13px;
}
.mode-switch {
  display: grid;
  width: 360px;
  grid-template-columns: 1fr 1fr;
  padding: 4px;
  border: 1px solid var(--cc-line);
  border-radius: 10px;
  background: #e9eef5;
}
.mode-switch button {
  display: flex;
  min-height: 39px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  border: 0;
  border-radius: 7px;
  color: var(--cc-muted);
  background: transparent;
  cursor: pointer;
  font-weight: 700;
}
.mode-switch button.active {
  color: var(--cc-primary-dark);
  background: #fff;
  box-shadow: 0 3px 9px #123f7d18;
}
.verify-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.panel {
  min-height: 510px;
  padding: 22px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.panel-title {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}
.panel-title > span {
  display: grid;
  width: 31px;
  height: 31px;
  place-items: center;
  border-radius: 8px;
  color: var(--cc-primary);
  background: var(--cc-primary-light);
  font-size: 10px;
  font-weight: 800;
}
.panel-title h2 {
  margin: 0;
  color: var(--cc-primary-dark);
  font-size: 17px;
}
.panel-title p {
  margin: 4px 0 0;
  color: var(--cc-muted);
  font-size: 10px;
}
.input-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.upload-box {
  position: relative;
  display: grid;
  min-height: 150px;
  place-items: center;
  align-content: center;
  gap: 6px;
  border: 1.5px dashed #aabbd0;
  border-radius: 10px;
  background: #f8fafc;
  cursor: pointer;
}
.upload-box.compact {
  min-height: 90px;
}
.upload-box input {
  position: absolute;
  width: 1px;
  height: 1px;
  clip-path: inset(50%);
}
.upload-box .el-icon {
  color: var(--cc-primary);
  font-size: 27px;
}
.upload-box strong {
  max-width: 85%;
  overflow: hidden;
  color: #34465d;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.upload-box span {
  color: var(--cc-muted);
  font-size: 10px;
}
.settings {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.settings label {
  display: grid;
  gap: 6px;
  color: #354256;
  font-size: 11px;
  font-weight: 700;
}
.input-panel > .el-button {
  width: 100%;
  margin-top: auto;
}
.verdict {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 15px;
  border: 1px solid #ecc7c4;
  border-radius: 10px;
  color: var(--cc-danger);
  background: #fff5f4;
}
.verdict.valid {
  border-color: #b9dcc8;
  color: var(--cc-success);
  background: #f1faf5;
}
.verdict > .el-icon {
  font-size: 30px;
}
.verdict strong,
.verdict span {
  display: block;
}
.verdict span {
  margin-top: 4px;
  color: var(--cc-muted);
  font-size: 10px;
}
.steps {
  display: grid;
  gap: 7px;
  margin: 15px 0;
  padding: 0;
  list-style: none;
}
.steps li {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 9px 11px;
  border-radius: 8px;
  color: var(--cc-danger);
  background: #fff7f6;
}
.steps li.passed {
  color: var(--cc-success);
  background: #f4faf6;
}
.steps strong,
.steps span {
  display: block;
}
.steps strong {
  font-size: 11px;
}
.steps span {
  margin-top: 2px;
  color: var(--cc-muted);
  font-size: 9px;
}
.result-panel > code {
  display: block;
  overflow: hidden;
  color: var(--cc-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.empty-result {
  display: grid;
  min-height: 380px;
  place-items: center;
  align-content: center;
  gap: 8px;
  color: var(--cc-muted);
  text-align: center;
}
.empty-result .el-icon {
  font-size: 38px;
}
.empty-result strong {
  color: #435168;
}
.empty-result span {
  font-size: 11px;
}
dl {
  display: grid;
  gap: 8px;
  margin: 18px 0;
}
dl div {
  display: flex;
  justify-content: space-between;
  gap: 15px;
  padding: 9px;
  border-bottom: 1px solid #edf0f4;
  font-size: 11px;
}
dt {
  color: var(--cc-muted);
}
dd {
  margin: 0;
  font-weight: 650;
}
@media (max-width: 900px) {
  .verify-layout {
    grid-template-columns: 1fr;
  }
  .mode-switch {
    width: 100%;
  }
}
</style>
