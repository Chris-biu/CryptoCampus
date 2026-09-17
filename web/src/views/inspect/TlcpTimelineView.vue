<script setup lang="ts">
import { computed, onMounted, ref, shallowRef } from 'vue'
import {
  ArrowLeft,
  Connection,
  DocumentChecked,
  Lock,
  Refresh,
  WarningFilled,
} from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import { getTlcpHandshake, type TlcpHandshake } from '@/api/inspect'
import { useSessionStore } from '@/stores/session'

type TimelineLane = 'client' | 'server' | 'gateway'

interface TimelineStep {
  index: number
  text: string
  lane: TimelineLane
  failed: boolean
  duration: string | null
}

const session = useSessionStore()
const handshake = shallowRef<TlcpHandshake | null>(null)
const isLoading = ref(false)
const errorMessage = ref('')
const activeStepIndex = ref(0)

const sensitiveText =
  /(-----BEGIN [A-Z ]*PRIVATE KEY-----|private[_ -]?key\s*[:=]|session[_ -]?key\s*[:=]|premaster[_ -]?secret\s*[:=]|raw[_ -]?capture[_ -]?credentials\s*[:=])/i
const failureText = /(失败|错误|拒绝|中止|alert|failed|failure|error|abort)/i

const timelineSteps = computed<TimelineStep[]>(() =>
  (handshake.value?.messages ?? []).slice(0, 30).map((message, index) => {
    const text = safeMessage(message)
    return {
      index,
      text,
      lane: messageLane(text),
      failed: failureText.test(text),
      duration: messageDuration(text),
    }
  }),
)
const activeStep = computed(() => timelineSteps.value[activeStepIndex.value] ?? null)
const failedStepIndex = computed(() => timelineSteps.value.findIndex((step) => step.failed))
const recordState = computed(() => {
  if (!handshake.value) return null
  if (failedStepIndex.value >= 0) {
    return { label: '记录含失败阶段', className: 'failed', icon: WarningFilled }
  }
  return { label: '网关记录已返回', className: 'received', icon: DocumentChecked }
})

function safeMessage(value: unknown, maxLength = 260): string {
  const normalized = typeof value === 'string' ? value.trim() : String(value)
  if (sensitiveText.test(normalized)) return '[敏感报文字段已隐藏]'
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized
}

function messageLane(message: string): TimelineLane {
  if (/^(client|客户端|clienthello)/i.test(message)) return 'client'
  if (/^(server|服务端|serverhello)/i.test(message)) return 'server'
  return 'gateway'
}

function messageDuration(message: string): string | null {
  return message.match(/\b\d+(?:\.\d+)?\s*ms\b/i)?.[0] ?? null
}

function failureMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 401)
    return '登录状态已失效，请重新登录后读取握手记录。'
  if (error instanceof ApiError && error.status === 403) return '当前账号无权读取 TLCP 握手记录。'
  if (error instanceof ApiError && (error.status === 404 || error.status === 501)) {
    return 'TLCP 抓包服务暂未开放。'
  }
  if (error instanceof ApiError && error.status === 503) return 'TLCP 网关或密码引擎暂不可用。'
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function selectStep(index: number): void {
  activeStepIndex.value = Math.min(Math.max(index, 0), timelineSteps.value.length - 1)
}

function moveStep(offset: number): void {
  if (timelineSteps.value.length === 0) return
  selectStep(activeStepIndex.value + offset)
}

function focusFailedStep(): void {
  if (failedStepIndex.value >= 0) selectStep(failedStepIndex.value)
}

async function captureHandshake(): Promise<void> {
  if (!session.accessToken || isLoading.value) return
  isLoading.value = true
  errorMessage.value = ''
  handshake.value = null
  activeStepIndex.value = 0
  try {
    handshake.value = await getTlcpHandshake(session.accessToken)
  } catch (error) {
    errorMessage.value = failureMessage(error)
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  // The first fetch is always the reviewed API. No local success sample is substituted on failure.
  void captureHandshake()
})
</script>

<template>
  <section class="tlcp-lab" aria-labelledby="tlcp-title">
    <header class="tlcp-heading">
      <div>
        <router-link class="back-link" :to="{ name: 'inspect' }">
          <el-icon><ArrowLeft /></el-icon>
          返回密码透视
        </router-link>
        <p class="eyebrow">教学视图 · GB/T 38636</p>
        <h1 id="tlcp-title">TLCP 双证书握手时序</h1>
        <p>只展示网关接口返回的脱敏握手字段，不读取私钥、预主密钥或完整报文。</p>
      </div>
      <el-button
        type="primary"
        :icon="Refresh"
        :loading="isLoading"
        data-testid="capture-handshake"
        @click="captureHandshake"
      >
        抓取一次脱敏握手
      </el-button>
    </header>

    <div class="source-banner">
      <span class="live-dot" :class="{ idle: !handshake }"></span>
      <div>
        <strong>{{ handshake ? '来源：真实 TLCP 网关脱敏接口' : '等待网关记录' }}</strong>
        <small>下方“协议结构示意”只在无记录时出现，不代表本次握手已经通过。</small>
      </div>
    </div>

    <el-alert
      v-if="errorMessage"
      title="无法读取 TLCP 握手记录"
      :description="errorMessage"
      type="warning"
      :closable="false"
      show-icon
    />

    <div v-if="isLoading" class="loading-stage" role="status" aria-live="polite">
      <span class="radar" aria-hidden="true"></span>
      <strong>正在等待网关返回脱敏记录</strong>
      <p>页面不会使用本地样例替代真实结果。</p>
    </div>

    <template v-else-if="handshake">
      <section class="session-strip" aria-label="TLCP 协议摘要">
        <div>
          <small>协议</small>
          <strong>{{ safeMessage(handshake.protocol, 24) }}</strong>
        </div>
        <div>
          <small>密码套件</small>
          <strong>{{ safeMessage(handshake.cipher_suite, 80) }}</strong>
        </div>
        <div>
          <small>报文阶段</small>
          <strong>{{ timelineSteps.length }}</strong>
        </div>
        <div v-if="recordState" class="record-state" :class="recordState.className">
          <el-icon><component :is="recordState.icon" /></el-icon>
          <strong>{{ recordState.label }}</strong>
          <small v-if="recordState.className === 'received'">接口未提供成功判定，不额外推断</small>
        </div>
      </section>

      <section class="certificate-pair" aria-labelledby="certificate-title">
        <div class="section-heading">
          <div>
            <p class="eyebrow">TLCP 特有路径</p>
            <h2 id="certificate-title">签名与加密证书各司其职</h2>
          </div>
          <el-tag effect="plain" type="success">双证书</el-tag>
        </div>
        <div class="certificate-grid">
          <article class="certificate-card signing">
            <span class="certificate-role"
              ><el-icon><DocumentChecked /></el-icon> 身份签名</span
            >
            <h3>签名证书</h3>
            <p>{{ safeMessage(handshake.signing_certificate) }}</p>
            <small>用于证明服务端身份并验证握手签名</small>
          </article>
          <div class="certificate-divider" aria-hidden="true"><span>≠</span></div>
          <article class="certificate-card encryption">
            <span class="certificate-role"
              ><el-icon><Lock /></el-icon> 密钥保护</span
            >
            <h3>加密证书</h3>
            <p>{{ safeMessage(handshake.encryption_certificate) }}</p>
            <small>用于 TLCP 密钥交换路径，不承担身份签名用途</small>
          </article>
        </div>
      </section>

      <section class="timeline-card" aria-labelledby="timeline-title">
        <div class="section-heading">
          <div>
            <p class="eyebrow">真实记录 · 点击查看</p>
            <h2 id="timeline-title">握手报文时序</h2>
          </div>
          <el-button
            v-if="failedStepIndex >= 0"
            type="danger"
            plain
            :icon="WarningFilled"
            data-testid="focus-failure"
            @click="focusFailedStep"
          >
            定位失败步骤
          </el-button>
        </div>

        <div v-if="timelineSteps.length === 0" class="message-empty">
          网关返回了握手摘要，但没有可展示的脱敏报文阶段。
        </div>
        <div v-else class="timeline-layout">
          <div class="timeline-actors" aria-hidden="true">
            <span>客户端</span><span>TLCP 网关</span><span>服务端</span>
          </div>
          <ol class="timeline" aria-label="TLCP 握手步骤，可用方向键切换">
            <li v-for="step in timelineSteps" :key="`${step.index}-${step.text}`">
              <button
                type="button"
                class="timeline-step"
                :class="[
                  step.lane,
                  { failed: step.failed, active: activeStepIndex === step.index },
                ]"
                :aria-current="activeStepIndex === step.index ? 'step' : undefined"
                :aria-label="`第 ${step.index + 1} 步：${step.text}`"
                @click="selectStep(step.index)"
                @keydown.left.prevent="moveStep(-1)"
                @keydown.up.prevent="moveStep(-1)"
                @keydown.right.prevent="moveStep(1)"
                @keydown.down.prevent="moveStep(1)"
              >
                <span class="step-number">{{ String(step.index + 1).padStart(2, '0') }}</span>
                <span class="step-copy">{{ step.text }}</span>
                <span v-if="step.duration" class="duration">{{ step.duration }}</span>
                <span v-if="step.failed" class="failure-label">失败</span>
              </button>
            </li>
          </ol>

          <aside class="step-inspector" aria-live="polite">
            <p class="eyebrow">当前步骤 {{ activeStepIndex + 1 }}</p>
            <h3>{{ activeStep?.failed ? '失败阶段' : '脱敏报文摘要' }}</h3>
            <p>{{ activeStep?.text }}</p>
            <dl v-if="activeStep">
              <div>
                <dt>方向</dt>
                <dd>
                  {{
                    { client: '客户端', server: '服务端', gateway: '网关/未标注' }[activeStep.lane]
                  }}
                </dd>
              </div>
              <div>
                <dt>耗时</dt>
                <dd>{{ activeStep.duration ?? '接口未单独提供' }}</dd>
              </div>
              <div>
                <dt>状态</dt>
                <dd>{{ activeStep.failed ? '后端摘要明确标记失败' : '未从文本推断成功' }}</dd>
              </div>
            </dl>
          </aside>
        </div>

        <details class="text-alternative">
          <summary>无障碍文本时序</summary>
          <ol>
            <li v-for="step in timelineSteps" :key="`text-${step.index}`">
              第 {{ step.index + 1 }} 步，{{ step.text }}{{ step.failed ? '，失败。' : '。' }}
            </li>
          </ol>
        </details>
      </section>
    </template>

    <section v-else-if="!errorMessage" class="protocol-guide" aria-labelledby="guide-title">
      <div class="guide-mark">
        <el-icon><Connection /></el-icon>
      </div>
      <div>
        <p class="eyebrow">协议结构示意 · 非抓包数据</p>
        <h2 id="guide-title">TLCP 为什么需要两张服务端证书？</h2>
        <p>
          签名证书证明身份，加密证书服务于密钥交换。点击“抓取一次脱敏握手”后，本示意会被真实接口记录替换。
        </p>
      </div>
      <ol>
        <li>ClientHello</li>
        <li>ServerHello</li>
        <li>签名证书 + 加密证书</li>
        <li>密钥交换与完成</li>
      </ol>
    </section>
  </section>
</template>

<style scoped>
.tlcp-lab {
  display: grid;
  gap: 16px;
}

.tlcp-heading,
.source-banner,
.session-strip,
.section-heading,
.certificate-role,
.record-state {
  display: flex;
  align-items: center;
}

.tlcp-heading {
  justify-content: space-between;
  gap: 24px;
}

.tlcp-heading h1,
.tlcp-heading p,
.section-heading h2,
.section-heading p,
.protocol-guide h2,
.protocol-guide p {
  margin: 0;
}

.tlcp-heading h1 {
  margin-top: 4px;
  color: var(--cc-primary-dark);
  font-size: clamp(26px, 3vw, 38px);
  letter-spacing: -0.035em;
}

.tlcp-heading > div > p:last-child {
  margin-top: 7px;
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

.source-banner {
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid #cbd9e9;
  border-radius: 10px;
  background: #f7faff;
}

.source-banner div {
  display: grid;
  gap: 2px;
}

.source-banner strong {
  color: var(--cc-primary-dark);
  font-size: 12px;
}

.source-banner small {
  color: var(--cc-muted);
}

.live-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--cc-success);
  box-shadow: 0 0 0 5px rgb(29 138 78 / 12%);
}

.live-dot.idle {
  background: #9aa7b6;
  box-shadow: 0 0 0 5px rgb(154 167 182 / 12%);
}

.loading-stage {
  display: grid;
  min-height: 450px;
  place-content: center;
  justify-items: center;
  padding: 40px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  color: var(--cc-muted);
  text-align: center;
}

.loading-stage strong {
  margin-top: 18px;
  color: var(--cc-primary-dark);
}

.loading-stage p {
  margin: 7px 0 0;
  font-size: 12px;
}

.radar {
  width: 62px;
  height: 62px;
  border: 1px solid #91afd2;
  border-radius: 50%;
  background: conic-gradient(from 90deg, transparent 0 75%, rgb(30 92 179 / 28%));
  animation: sweep 1.2s linear infinite;
}

.session-strip {
  display: grid;
  grid-template-columns: 0.55fr 1.5fr 0.55fr 1.2fr;
  overflow: hidden;
  border: 1px solid #c7d5e7;
  border-radius: 12px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}

.session-strip > div {
  display: grid;
  min-width: 0;
  gap: 5px;
  padding: 14px 16px;
  border-right: 1px solid #e1e7ef;
}

.session-strip small {
  color: var(--cc-muted);
  font-size: 10px;
}

.session-strip strong {
  overflow: hidden;
  color: var(--cc-primary-dark);
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.session-strip .record-state {
  display: flex;
  align-items: center;
  gap: 9px;
  border-right: 0;
}

.record-state .el-icon {
  flex: 0 0 auto;
  font-size: 20px;
}

.record-state.received {
  color: #176f40;
  background: #edf8f1;
}

.record-state.failed {
  color: #8b3028;
  background: #fff1f0;
}

.record-state strong {
  color: inherit;
  font-family: inherit;
}

.record-state small {
  color: inherit;
  opacity: 0.8;
}

.certificate-pair,
.timeline-card {
  padding: 19px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: var(--cc-card);
  box-shadow: var(--cc-shadow);
}

.section-heading {
  justify-content: space-between;
  gap: 16px;
}

.section-heading h2 {
  margin-top: 4px;
  color: var(--cc-primary-dark);
  font-size: 19px;
}

.certificate-grid {
  display: grid;
  grid-template-columns: 1fr 42px 1fr;
  align-items: stretch;
  gap: 12px;
  margin-top: 15px;
}

.certificate-card {
  position: relative;
  min-width: 0;
  padding: 16px;
  overflow: hidden;
  border: 1px solid #d5deea;
  border-radius: 11px;
}

.certificate-card::after {
  position: absolute;
  top: -28px;
  right: -18px;
  width: 96px;
  height: 96px;
  border: 18px solid rgb(30 92 179 / 6%);
  border-radius: 50%;
  content: '';
}

.certificate-card.encryption::after {
  border-color: rgb(107 70 193 / 7%);
}

.certificate-role {
  gap: 6px;
  color: var(--cc-primary);
  font-size: 11px;
  font-weight: 750;
}

.certificate-card.encryption .certificate-role {
  color: #6b46c1;
}

.certificate-card h3 {
  margin: 8px 0 6px;
  color: var(--cc-primary-dark);
}

.certificate-card p {
  position: relative;
  z-index: 1;
  overflow-wrap: anywhere;
  margin: 0;
  color: #344256;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 11px;
  line-height: 1.55;
}

.certificate-card small {
  display: block;
  margin-top: 9px;
  color: var(--cc-muted);
  line-height: 1.5;
}

.certificate-divider {
  display: grid;
  place-items: center;
}

.certificate-divider span {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border: 1px dashed #9aacca;
  border-radius: 50%;
  color: #6f829a;
  font-weight: 800;
}

.timeline-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(250px, 0.55fr);
  gap: 14px;
  margin-top: 16px;
}

.timeline-actors {
  grid-column: 1;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  padding: 0 10px 8px;
  color: var(--cc-muted);
  font-size: 10px;
  font-weight: 700;
  text-align: center;
}

.timeline {
  position: relative;
  grid-column: 1;
  display: grid;
  max-height: 310px;
  gap: 7px;
  margin: 0;
  padding: 8px 12px;
  overflow-y: auto;
  border-radius: 10px;
  background:
    linear-gradient(
      90deg,
      transparent 16.5%,
      #dce4ee 16.5% 16.7%,
      transparent 16.7% 49.9%,
      #dce4ee 49.9% 50.1%,
      transparent 50.1% 83.2%,
      #dce4ee 83.2% 83.4%,
      transparent 83.4%
    ),
    #f8fafc;
  list-style: none;
}

.timeline-step {
  position: relative;
  display: grid;
  width: 72%;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 8px;
  padding: 9px 10px;
  border: 1px solid #d7e0eb;
  border-radius: 8px;
  color: #334155;
  background: #fff;
  cursor: pointer;
  text-align: left;
}

.timeline-step.client {
  justify-self: start;
  border-left: 3px solid #2c6dbd;
}

.timeline-step.server {
  justify-self: end;
  border-right: 3px solid #6b46c1;
}

.timeline-step.gateway {
  justify-self: center;
  border-left: 3px solid #718096;
}

.timeline-step.active {
  border-color: var(--cc-primary);
  box-shadow: 0 0 0 3px rgb(30 92 179 / 12%);
}

.timeline-step.failed {
  border-color: #d86960;
  color: #7f2821;
  background: #fff4f3;
}

.step-number,
.duration,
.failure-label {
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 9px;
}

.step-number {
  color: var(--cc-primary);
  font-weight: 800;
}

.step-copy {
  overflow: hidden;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.duration {
  color: var(--cc-muted);
}

.failure-label {
  padding: 2px 5px;
  border-radius: 4px;
  color: #fff;
  background: var(--cc-danger);
}

.step-inspector {
  grid-row: 1 / span 2;
  grid-column: 2;
  min-width: 0;
  padding: 16px;
  border: 1px solid #d5deea;
  border-radius: 10px;
  background: linear-gradient(145deg, #fff, #f5f8fc);
}

.step-inspector h3 {
  margin: 7px 0;
  color: var(--cc-primary-dark);
}

.step-inspector > p:not(.eyebrow) {
  overflow-wrap: anywhere;
  color: #334155;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 11px;
  line-height: 1.65;
}

.step-inspector dl {
  display: grid;
  gap: 8px;
  margin: 16px 0 0;
}

.step-inspector dl div {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding-top: 8px;
  border-top: 1px solid #e0e6ee;
  font-size: 10px;
}

.step-inspector dt {
  color: var(--cc-muted);
}

.step-inspector dd {
  margin: 0;
  color: var(--cc-ink);
  text-align: right;
}

.text-alternative {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid #e3e8ef;
  color: var(--cc-muted);
  font-size: 11px;
}

.text-alternative summary {
  color: var(--cc-primary);
  cursor: pointer;
  font-weight: 700;
}

.text-alternative ol {
  line-height: 1.7;
}

.message-empty {
  margin-top: 15px;
  padding: 26px;
  border: 1px dashed #b6c4d5;
  border-radius: 10px;
  color: var(--cc-muted);
  text-align: center;
}

.protocol-guide {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 16px 18px;
  padding: 24px;
  border: 1px dashed #9fb5d0;
  border-radius: 14px;
  background: #f8fbff;
}

.guide-mark {
  display: grid;
  width: 52px;
  height: 52px;
  grid-row: span 2;
  place-items: center;
  border-radius: 13px;
  color: #fff;
  background: var(--cc-primary-dark);
  font-size: 26px;
}

.protocol-guide h2 {
  margin-top: 5px;
  color: var(--cc-primary-dark);
}

.protocol-guide > div p:last-child {
  margin-top: 7px;
  color: var(--cc-muted);
  line-height: 1.65;
}

.protocol-guide ol {
  grid-column: 2;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.protocol-guide li {
  padding: 6px 9px;
  border-radius: 6px;
  color: #43536a;
  background: #e8f0fb;
  font-family: 'Cascadia Code', Consolas, monospace;
  font-size: 10px;
}

@keyframes sweep {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 980px) {
  .session-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .session-strip > div:nth-child(2) {
    border-right: 0;
  }

  .timeline-layout {
    grid-template-columns: 1fr;
  }

  .step-inspector {
    grid-row: auto;
    grid-column: 1;
  }
}

@media (max-width: 680px) {
  .tlcp-heading {
    align-items: stretch;
    flex-direction: column;
  }

  .certificate-grid,
  .session-strip {
    grid-template-columns: 1fr;
  }

  .certificate-divider {
    height: 24px;
  }

  .session-strip > div {
    border-right: 0;
    border-bottom: 1px solid #e1e7ef;
  }

  .timeline-step {
    width: 92%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .radar {
    animation: none;
  }
}
</style>
