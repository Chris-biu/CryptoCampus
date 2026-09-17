<script setup lang="ts">
/* global document, URL, File, Event, HTMLInputElement */
import { computed, onMounted, reactive, ref, shallowRef } from 'vue'
import { useRouter } from 'vue-router'
import {
  CircleCheck,
  Connection,
  DataAnalysis,
  Download,
  Key,
  Lock,
  Refresh,
  RefreshLeft,
  SwitchButton,
  Upload,
  User,
  Warning,
} from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import {
  changePassword,
  deleteAccount,
  exportKeyringBackup,
  getKeyring,
  getMe,
  getQuotas,
  importKeyringBackup,
  listSessions,
  revokeSession,
  rotateKeyring,
  verifyOwnCertificate,
  type DeviceSession,
  type KeyringSummary,
  type Quota,
  type User as CurrentUser,
} from '@/api/me'
import { useSessionStore } from '@/stores/session'

type FeedbackType = 'success' | 'error'

interface Feedback {
  message: string
  type: FeedbackType
}

const session = useSessionStore()
const router = useRouter()
const profile = shallowRef<CurrentUser | null>(session.currentUser)
const keyring = shallowRef<KeyringSummary | null>(null)
const sessions = shallowRef<ReadonlyArray<DeviceSession>>([])
const quotas = shallowRef<ReadonlyArray<Quota>>([])
const quotasResetAt = ref<string | null>(null)

const loading = reactive({ profile: false, keyring: false, sessions: false, quotas: false })
const errors = reactive({ profile: '', keyring: '', sessions: '', quotas: '' })

const passwordForm = reactive({ currentPassword: '', newPassword: '', confirmPassword: '' })
const passwordSubmitting = ref(false)
const passwordFeedback = shallowRef<Feedback | null>(null)

const rotationOpen = ref(false)
const rotationPassword = ref('')
const rotationAcknowledged = ref(false)
const rotationSubmitting = ref(false)
const rotationFeedback = shallowRef<Feedback | null>(null)

const revokeTarget = shallowRef<DeviceSession | null>(null)
const revokingSessionId = ref<string | null>(null)
const sessionFeedback = shallowRef<Feedback | null>(null)
const backupMode = ref<'export' | 'import' | null>(null)
const backupPassword = ref('')
const backupFile = shallowRef<File | null>(null)
const backupSubmitting = ref(false)
const backupFeedback = shallowRef<Feedback | null>(null)
const deletionOpen = ref(false)
const deletionPassword = ref('')
const deletionConfirmation = ref('')
const deletionSubmitting = ref(false)
const deletionFeedback = shallowRef<Feedback | null>(null)
const certificateVerifying = ref(false)
const certificateFeedback = shallowRef<Feedback | null>(null)

const accessToken = computed(() => session.accessToken)
const displayUser = computed(() => profile.value ?? session.currentUser)
const isAnyLoading = computed(() => Object.values(loading).some(Boolean))

const roleLabels = {
  student: '学生用户',
  admin: '管理员',
  teacher: '教师',
  system: '系统账号',
} as const

const statusLabels = {
  active: '正常',
  frozen: '已冻结',
  deleted: '已注销',
} as const

const quotaLabels: Record<Quota['resource'], { label: string; unit: string; note: string }> = {
  hole_credential: { label: '树洞凭证申领', unit: '张', note: '每日重置' },
  interaction_credential: { label: '评论与点赞凭证', unit: '张', note: '每日重置' },
  drop: { label: '密信创建', unit: '封', note: '单封不超过 100 MiB' },
  vote_ballot: { label: '投票选票', unit: '张', note: '每场投票限领一张' },
}

function apiMessage(error: unknown): string {
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

function formatDate(value: string | null | undefined, withTime = false): string {
  if (!value) return '未提供'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '未提供'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}),
  }).format(date)
}

function formatRelativeTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '时间未知'
  const differenceMinutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000))
  if (differenceMinutes < 1) return '刚刚'
  if (differenceMinutes < 60) return `${differenceMinutes} 分钟前`
  if (differenceMinutes < 24 * 60) return `${Math.floor(differenceMinutes / 60)} 小时前`
  return formatDate(value, true)
}

function keyKindLabel(kind: KeyringSummary['items'][number]['kind']): string {
  return {
    sm2_identity: 'SM2 身份密钥',
    certificate: '用户证书',
    ml_kem: 'ML-KEM-768 密钥',
  }[kind]
}

function keyStatus(status: KeyringSummary['items'][number]['status']): {
  label: string
  type: 'success' | 'warning' | 'danger' | 'info'
} {
  return {
    active: { label: '有效', type: 'success' as const },
    expired: { label: '已过期', type: 'warning' as const },
    revoked: { label: '已吊销', type: 'danger' as const },
    unavailable: { label: '不可用', type: 'info' as const },
  }[status]
}

function quotaPercentage(quota: Quota): number {
  return Math.min(100, Math.round((quota.used / quota.limit) * 100))
}

function quotaColor(quota: Quota): string {
  const percentage = quotaPercentage(quota)
  if (percentage >= 100) return '#c8382e'
  if (percentage >= 80) return '#b07a12'
  return '#236fbd'
}

async function loadProfile(): Promise<void> {
  if (!accessToken.value) return
  loading.profile = true
  errors.profile = ''
  try {
    profile.value = await getMe(accessToken.value)
  } catch (error) {
    errors.profile = `账户信息暂不可用：${apiMessage(error)}`
  } finally {
    loading.profile = false
  }
}

async function loadKeyringSummary(): Promise<void> {
  if (!accessToken.value) return
  loading.keyring = true
  errors.keyring = ''
  try {
    keyring.value = await getKeyring(accessToken.value)
  } catch (error) {
    keyring.value = null
    errors.keyring = `密钥环暂不可用：${apiMessage(error)}`
  } finally {
    loading.keyring = false
  }
}

async function loadSessionList(): Promise<void> {
  if (!accessToken.value) return
  loading.sessions = true
  errors.sessions = ''
  try {
    sessions.value = (await listSessions(accessToken.value)).items
  } catch (error) {
    sessions.value = []
    errors.sessions = `登录设备暂不可用：${apiMessage(error)}`
  } finally {
    loading.sessions = false
  }
}

async function loadQuotaSummary(): Promise<void> {
  if (!accessToken.value) return
  loading.quotas = true
  errors.quotas = ''
  try {
    const response = await getQuotas(accessToken.value)
    quotas.value = response.items
    quotasResetAt.value = response.resets_at
  } catch (error) {
    quotas.value = []
    quotasResetAt.value = null
    errors.quotas = `服务额度暂不可用：${apiMessage(error)}`
  } finally {
    loading.quotas = false
  }
}

async function refreshPage(): Promise<void> {
  await Promise.all([loadProfile(), loadKeyringSummary(), loadSessionList(), loadQuotaSummary()])
}

async function verifyCertificate(): Promise<void> {
  if (!accessToken.value || certificateVerifying.value) return
  certificateVerifying.value = true
  certificateFeedback.value = null
  try {
    const result = await verifyOwnCertificate(accessToken.value)
    certificateFeedback.value = result.valid
      ? { message: '证书链、有效期与吊销状态验证通过。', type: 'success' }
      : {
          message: `证书验证未通过（${result.state === 'revoked' ? '已吊销' : result.state === 'expired' ? '已过期' : '证书无效'}）。`,
          type: 'error',
        }
  } catch (error) {
    certificateFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    certificateVerifying.value = false
  }
}

function validatePasswordForm(): string | null {
  if (!passwordForm.currentPassword) return '请输入当前口令。'
  if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{10,128}$/.test(passwordForm.newPassword)) {
    return '新口令需为 10–128 位，并同时包含大写字母、小写字母和数字。'
  }
  if (passwordForm.newPassword !== passwordForm.confirmPassword) return '两次输入的新口令不一致。'
  return null
}

async function submitPassword(): Promise<void> {
  if (!accessToken.value || passwordSubmitting.value) return
  passwordFeedback.value = null
  const validationMessage = validatePasswordForm()
  if (validationMessage) {
    passwordFeedback.value = { message: validationMessage, type: 'error' }
    return
  }

  passwordSubmitting.value = true
  try {
    await changePassword(
      {
        current_password: passwordForm.currentPassword,
        new_password: passwordForm.newPassword,
      },
      accessToken.value,
    )
    passwordFeedback.value = {
      message: '口令已更新，公钥与证书保持不变。',
      type: 'success',
    }
  } catch (error) {
    passwordFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    passwordSubmitting.value = false
    passwordForm.currentPassword = ''
    passwordForm.newPassword = ''
    passwordForm.confirmPassword = ''
  }
}

function openRotation(): void {
  rotationPassword.value = ''
  rotationAcknowledged.value = false
  rotationFeedback.value = null
  rotationOpen.value = true
}

function cancelRotation(): void {
  rotationPassword.value = ''
  rotationAcknowledged.value = false
  rotationOpen.value = false
}

async function submitRotation(): Promise<void> {
  if (
    !accessToken.value ||
    !rotationPassword.value ||
    !rotationAcknowledged.value ||
    rotationSubmitting.value
  )
    return

  rotationSubmitting.value = true
  rotationFeedback.value = null
  try {
    keyring.value = await rotateKeyring(
      { password: rotationPassword.value, acknowledge_inflight_loss: true },
      globalThis.crypto.randomUUID(),
      accessToken.value,
    )
    rotationFeedback.value = {
      message: '密钥环已重新生成，旧证书已进入吊销流程。',
      type: 'success',
    }
    rotationOpen.value = false
  } catch (error) {
    rotationFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    rotationSubmitting.value = false
    rotationPassword.value = ''
    rotationAcknowledged.value = false
  }
}

function requestRevoke(target: DeviceSession): void {
  if (target.current) return
  sessionFeedback.value = null
  revokeTarget.value = target
}

function cancelRevoke(): void {
  revokeTarget.value = null
}

async function confirmRevoke(): Promise<void> {
  if (!accessToken.value || !revokeTarget.value || revokingSessionId.value) return
  const target = revokeTarget.value
  revokingSessionId.value = target.id
  sessionFeedback.value = null
  try {
    await revokeSession(target.id, accessToken.value)
    sessions.value = sessions.value.filter((item) => item.id !== target.id)
    sessionFeedback.value = { message: `已远程登出“${target.device}”。`, type: 'success' }
    revokeTarget.value = null
  } catch (error) {
    sessionFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    revokingSessionId.value = null
  }
}

function openBackup(mode: 'export' | 'import'): void {
  backupMode.value = mode
  backupPassword.value = ''
  backupFile.value = null
  backupFeedback.value = null
}

function closeBackup(): void {
  if (backupSubmitting.value) return
  backupMode.value = null
  backupPassword.value = ''
  backupFile.value = null
}

function selectBackup(event: Event): void {
  const input = event.target as HTMLInputElement
  backupFile.value = input.files?.[0] ?? null
}

async function submitBackup(): Promise<void> {
  if (!accessToken.value || !backupMode.value || !backupPassword.value || backupSubmitting.value)
    return
  if (backupMode.value === 'import' && !backupFile.value) return

  backupSubmitting.value = true
  backupFeedback.value = null
  try {
    if (backupMode.value === 'export') {
      const backup = await exportKeyringBackup(
        { password: backupPassword.value },
        accessToken.value,
      )
      const url = URL.createObjectURL(backup)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `cryptocampus-keyring-${new Date().toISOString().slice(0, 10)}.pem`
      anchor.click()
      URL.revokeObjectURL(url)
      backupFeedback.value = { message: '口令加密的密钥环备份已下载。', type: 'success' }
    } else {
      keyring.value = await importKeyringBackup(
        backupFile.value!,
        backupPassword.value,
        accessToken.value,
      )
      backupFeedback.value = { message: '密钥环已从加密备份恢复。', type: 'success' }
    }
    backupMode.value = null
  } catch (error) {
    backupFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    backupSubmitting.value = false
    backupPassword.value = ''
    backupFile.value = null
  }
}

function openDeletion(): void {
  deletionOpen.value = true
  deletionPassword.value = ''
  deletionConfirmation.value = ''
  deletionFeedback.value = null
}

async function submitDeletion(): Promise<void> {
  if (
    !accessToken.value ||
    !deletionPassword.value ||
    deletionConfirmation.value !== 'DELETE_MY_ACCOUNT' ||
    deletionSubmitting.value
  )
    return
  deletionSubmitting.value = true
  deletionFeedback.value = null
  try {
    await deleteAccount(
      { password: deletionPassword.value, confirm: 'DELETE_MY_ACCOUNT' },
      accessToken.value,
    )
    session.clear()
    await router.replace({ name: 'login' })
  } catch (error) {
    deletionFeedback.value = { message: apiMessage(error), type: 'error' }
  } finally {
    deletionSubmitting.value = false
    deletionPassword.value = ''
  }
}

onMounted(() => {
  void refreshPage()
})
</script>

<template>
  <section class="me-page" aria-labelledby="me-page-title">
    <header v-loading="loading.profile" class="me-profile-banner">
      <div class="me-profile-identity">
        <span class="me-avatar" aria-hidden="true">
          {{ displayUser?.email.charAt(0).toUpperCase() ?? 'U' }}
        </span>
        <div>
          <p class="eyebrow">P11 · 账户与密钥环管理</p>
          <h1 id="me-page-title">用户中心</h1>
          <p>{{ displayUser?.email ?? '账户信息读取中' }}</p>
        </div>
      </div>
      <div class="me-profile-meta">
        <el-tag type="primary" effect="plain" round>
          {{ displayUser ? roleLabels[displayUser.role] : '角色未知' }}
        </el-tag>
        <el-tag
          :type="displayUser?.status === 'active' ? 'success' : 'warning'"
          effect="plain"
          round
        >
          {{ displayUser ? statusLabels[displayUser.status] : '状态未知' }}
        </el-tag>
        <span>注册于 {{ formatDate(displayUser?.created_at) }}</span>
        <el-button :icon="Refresh" :loading="isAnyLoading" @click="refreshPage">
          刷新状态
        </el-button>
      </div>
      <el-alert
        v-if="errors.profile"
        class="me-banner-error"
        :title="errors.profile"
        type="warning"
        show-icon
        :closable="false"
      />
    </header>

    <div class="me-grid">
      <div class="me-column">
        <article class="me-card" aria-labelledby="password-title">
          <div class="me-card-heading">
            <span class="me-card-icon"
              ><el-icon><Lock /></el-icon
            ></span>
            <div>
              <span class="me-section-number">01</span>
              <h2 id="password-title">修改口令</h2>
            </div>
          </div>

          <form class="me-form" @submit.prevent="submitPassword">
            <label for="current-password">当前口令</label>
            <el-input
              id="current-password"
              v-model="passwordForm.currentPassword"
              data-testid="current-password"
              type="password"
              autocomplete="current-password"
              show-password
            />
            <label for="new-password">新口令</label>
            <el-input
              id="new-password"
              v-model="passwordForm.newPassword"
              data-testid="new-password"
              type="password"
              autocomplete="new-password"
              show-password
            />
            <small>10–128 位，同时包含大写字母、小写字母和数字。</small>
            <label for="confirm-password">确认新口令</label>
            <el-input
              id="confirm-password"
              v-model="passwordForm.confirmPassword"
              data-testid="confirm-password"
              type="password"
              autocomplete="new-password"
              show-password
            />
            <el-alert
              v-if="passwordFeedback"
              :title="passwordFeedback.message"
              :type="passwordFeedback.type"
              show-icon
              :closable="false"
            />
            <el-button
              data-testid="change-password"
              native-type="submit"
              type="primary"
              :loading="passwordSubmitting"
            >
              更新口令
            </el-button>
          </form>

          <div class="me-note">
            <el-icon><CircleCheck /></el-icon>
            <p>
              新口令只用于重新派生 KEK
              并加密原私钥。整个过程在服务端内存完成，<strong>公钥与证书不会改变</strong>。
            </p>
          </div>
        </article>

        <article v-loading="loading.keyring" class="me-card" aria-labelledby="keyring-title">
          <div class="me-card-heading me-card-heading-row">
            <div class="me-card-heading">
              <span class="me-card-icon"
                ><el-icon><Key /></el-icon
              ></span>
              <div>
                <span class="me-section-number">02</span>
                <h2 id="keyring-title">密钥环管理</h2>
              </div>
            </div>
            <el-tag effect="plain" type="info">
              解锁至 {{ formatDate(keyring?.unlocked_until, true) }}
            </el-tag>
          </div>

          <el-alert
            v-if="errors.keyring"
            :title="errors.keyring"
            type="warning"
            show-icon
            :closable="false"
          />
          <div v-else-if="keyring?.items.length" class="me-table-wrap">
            <table class="me-table">
              <caption class="sr-only">
                密钥环摘要
              </caption>
              <thead>
                <tr>
                  <th>密钥</th>
                  <th>算法</th>
                  <th>指纹（脱敏）</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in keyring.items" :key="`${item.kind}-${item.fingerprint}`">
                  <td>{{ keyKindLabel(item.kind) }}</td>
                  <td>{{ item.algorithm }}</td>
                  <td>
                    <code>{{ item.fingerprint }}</code>
                  </td>
                  <td>
                    <el-tag :type="keyStatus(item.status).type" effect="plain" size="small">
                      {{ keyStatus(item.status).label }}
                    </el-tag>
                    <small v-if="item.expires_at">至 {{ formatDate(item.expires_at) }}</small>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <el-empty
            v-else-if="!loading.keyring"
            :image-size="58"
            description="当前没有可展示的密钥或证书"
          />

          <div class="me-action-row">
            <el-button
              data-testid="open-backup-export"
              :icon="Download"
              @click="openBackup('export')"
              >导出备份</el-button
            >
            <el-button data-testid="open-backup-import" :icon="Upload" @click="openBackup('import')"
              >导入恢复</el-button
            >
            <el-button
              data-testid="open-rotation"
              type="danger"
              plain
              :icon="RefreshLeft"
              @click="openRotation"
            >
              重新生成密钥对
            </el-button>
          </div>

          <div
            v-if="rotationOpen"
            class="danger-confirmation"
            role="group"
            aria-labelledby="rotation-confirm-title"
          >
            <div class="danger-confirmation-title">
              <el-icon><Warning /></el-icon>
              <strong id="rotation-confirm-title">确认重新生成密钥对</strong>
            </div>
            <p>旧证书将进入 CRL，他人使用旧公钥加密的在途密信可能无法解密。操作前请先确认风险。</p>
            <el-checkbox v-model="rotationAcknowledged" data-testid="rotation-acknowledgement">
              我已了解在途密信无法解密的风险
            </el-checkbox>
            <label for="rotation-password">输入当前口令进行二次确认</label>
            <el-input
              id="rotation-password"
              v-model="rotationPassword"
              data-testid="rotation-password"
              type="password"
              autocomplete="current-password"
              show-password
            />
            <div class="danger-confirmation-actions">
              <el-button @click="cancelRotation">取消</el-button>
              <el-button
                data-testid="confirm-rotation"
                type="danger"
                :disabled="!rotationPassword || !rotationAcknowledged"
                :loading="rotationSubmitting"
                @click="submitRotation"
              >
                确认重新生成
              </el-button>
            </div>
          </div>
          <el-alert
            v-if="backupFeedback"
            class="me-feedback"
            :title="backupFeedback.message"
            :type="backupFeedback.type"
            show-icon
            :closable="false"
          />
          <el-alert
            v-if="rotationFeedback"
            class="me-feedback"
            :title="rotationFeedback.message"
            :type="rotationFeedback.type"
            show-icon
            :closable="false"
          />
        </article>

        <article v-loading="loading.sessions" class="me-card" aria-labelledby="sessions-title">
          <div class="me-card-heading">
            <span class="me-card-icon"
              ><el-icon><Connection /></el-icon
            ></span>
            <div>
              <span class="me-section-number">03</span>
              <h2 id="sessions-title">登录设备与会话</h2>
            </div>
          </div>

          <el-alert
            v-if="errors.sessions"
            :title="errors.sessions"
            type="warning"
            show-icon
            :closable="false"
          />
          <div v-else-if="sessions.length" class="me-table-wrap">
            <table class="me-table sessions-table">
              <caption class="sr-only">
                登录设备列表
              </caption>
              <thead>
                <tr>
                  <th>设备</th>
                  <th>IP</th>
                  <th>最后活跃</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in sessions" :key="item.id">
                  <td>{{ item.device }}</td>
                  <td>
                    <code>{{ item.ip_masked }}</code>
                  </td>
                  <td>{{ formatRelativeTime(item.last_active_at) }}</td>
                  <td>
                    <el-tag v-if="item.current" type="success" effect="plain" size="small"
                      >当前设备</el-tag
                    >
                    <el-button
                      v-else
                      data-testid="revoke-session"
                      type="danger"
                      plain
                      size="small"
                      :loading="revokingSessionId === item.id"
                      @click="requestRevoke(item)"
                    >
                      远程登出
                    </el-button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <el-empty
            v-else-if="!loading.sessions"
            :image-size="58"
            description="当前没有可展示的登录设备"
          />

          <div v-if="revokeTarget" class="inline-confirmation" role="alert">
            <span
              >确认远程登出“{{ revokeTarget.device }}”？该设备的 refresh token 将立即失效。</span
            >
            <div>
              <el-button size="small" @click="cancelRevoke">取消</el-button>
              <el-button
                data-testid="confirm-revoke"
                size="small"
                type="danger"
                @click="confirmRevoke"
                >确认登出</el-button
              >
            </div>
          </div>
          <el-alert
            v-if="sessionFeedback"
            class="me-feedback"
            :title="sessionFeedback.message"
            :type="sessionFeedback.type"
            show-icon
            :closable="false"
          />
          <div class="me-note">
            <el-icon><Lock /></el-icon>
            <p>私钥解锁缓存 TTL 为 15 分钟；远程登出会吊销目标设备的 refresh token。</p>
          </div>
        </article>
      </div>

      <div class="me-column">
        <article v-loading="loading.quotas" class="me-card" aria-labelledby="quotas-title">
          <div class="me-card-heading me-card-heading-row">
            <div class="me-card-heading">
              <span class="me-card-icon"
                ><el-icon><DataAnalysis /></el-icon
              ></span>
              <div>
                <span class="me-section-number">04</span>
                <h2 id="quotas-title">我的服务额度（今日）</h2>
              </div>
            </div>
            <span class="quota-reset">重置于 {{ formatDate(quotasResetAt, true) }}</span>
          </div>

          <el-alert
            v-if="errors.quotas"
            :title="errors.quotas"
            type="warning"
            show-icon
            :closable="false"
          />
          <div v-else-if="quotas.length" class="quota-list">
            <div v-for="quota in quotas" :key="quota.resource" class="quota-item">
              <div class="quota-heading">
                <div>
                  <strong>{{ quotaLabels[quota.resource].label }}</strong
                  ><small>{{ quotaLabels[quota.resource].note }}</small>
                </div>
                <span
                  >{{ quota.used }} / {{ quota.limit }} {{ quotaLabels[quota.resource].unit }}</span
                >
              </div>
              <el-progress
                :percentage="quotaPercentage(quota)"
                :color="quotaColor(quota)"
                :stroke-width="8"
                :show-text="false"
              />
            </div>
          </div>
          <el-empty
            v-else-if="!loading.quotas"
            :image-size="58"
            description="今日额度数据暂未提供"
          />
        </article>

        <article class="me-card privacy-card" aria-labelledby="privacy-title">
          <div class="me-card-heading">
            <span class="me-card-icon"
              ><el-icon><User /></el-icon
            ></span>
            <div>
              <span class="me-section-number">05</span>
              <h2 id="privacy-title">隐私边界（服务器知道什么）</h2>
            </div>
          </div>
          <div class="me-table-wrap">
            <table class="me-table privacy-table">
              <caption class="sr-only">
                服务器数据可见性说明
              </caption>
              <thead>
                <tr>
                  <th>数据</th>
                  <th>服务器可见性</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>你的口令、KEK、私钥明文</td>
                  <td><span class="privacy-no">持久化层不保存明文</span></td>
                </tr>
                <tr>
                  <td>密信内容、树洞帖归属、选票归属</td>
                  <td><span class="privacy-no">加密或匿名，不可见</span></td>
                </tr>
                <tr>
                  <td>凭证申领次数、密信创建元数据</td>
                  <td><span class="privacy-yes">防滥用所需，按期保留</span></td>
                </tr>
                <tr>
                  <td>登录设备、脱敏 IP 与操作元信息</td>
                  <td><span class="privacy-yes">按权限可见</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="me-note privacy-note">
            <el-icon><CircleCheck /></el-icon>
            <p>
              管理员可以治理账号和销毁密文，但不能解密用户内容；必要的密码运算仅在后端内存中短暂处理，持久化层只保存密文或摘要。
            </p>
          </div>
        </article>

        <article class="me-card account-actions-card" aria-labelledby="account-actions-title">
          <div class="me-card-heading">
            <span class="me-card-icon"
              ><el-icon><SwitchButton /></el-icon
            ></span>
            <div>
              <span class="me-section-number">06</span>
              <h2 id="account-actions-title">账号操作</h2>
            </div>
          </div>
          <div class="me-action-row">
            <el-button
              data-testid="verify-certificate"
              :icon="CircleCheck"
              :loading="certificateVerifying"
              @click="verifyCertificate"
              >验证我的证书链</el-button
            >
            <el-button data-testid="open-account-deletion" type="danger" plain @click="openDeletion"
              >注销账号</el-button
            >
          </div>
          <el-alert
            v-if="certificateFeedback"
            class="me-feedback"
            :title="certificateFeedback.message"
            :type="certificateFeedback.type"
            show-icon
            :closable="false"
          />
          <div v-if="deletionOpen" class="danger-confirmation" role="group">
            <div class="danger-confirmation-title">
              <el-icon><Warning /></el-icon><strong>确认注销账号</strong>
            </div>
            <p>该操作会删除密钥环并吊销证书。请输入当前口令，并完整输入 DELETE_MY_ACCOUNT。</p>
            <label for="deletion-password">当前口令</label>
            <el-input
              id="deletion-password"
              v-model="deletionPassword"
              data-testid="deletion-password"
              type="password"
              autocomplete="current-password"
              show-password
            />
            <label for="deletion-confirmation">确认短语</label>
            <el-input
              id="deletion-confirmation"
              v-model="deletionConfirmation"
              data-testid="deletion-confirmation"
              autocomplete="off"
            />
            <div class="danger-confirmation-actions">
              <el-button @click="deletionOpen = false">取消</el-button>
              <el-button
                data-testid="confirm-account-deletion"
                type="danger"
                :loading="deletionSubmitting"
                :disabled="!deletionPassword || deletionConfirmation !== 'DELETE_MY_ACCOUNT'"
                @click="submitDeletion"
                >永久注销</el-button
              >
            </div>
          </div>
          <el-alert
            v-if="deletionFeedback"
            class="me-feedback"
            :title="deletionFeedback.message"
            :type="deletionFeedback.type"
            show-icon
            :closable="false"
          />
          <div class="me-note danger-note">
            <el-icon><Warning /></el-icon>
            <p>
              注销应删除密钥环并吊销证书；密信按剩余 TTL 销毁，凭证申领记录保留 30
              天后删除。注销请求失败时页面会保留登录态并显示稳定错误。
            </p>
          </div>
        </article>
      </div>
    </div>
  </section>

  <el-dialog
    :model-value="backupMode !== null"
    :title="backupMode === 'export' ? '导出加密备份' : '导入加密备份'"
    width="min(520px, 94vw)"
    :close-on-click-modal="!backupSubmitting"
    @close="closeBackup"
  >
    <div class="backup-form">
      <p>备份文件必须使用独立强口令加密；页面不会保存口令或文件内容。</p>
      <label for="backup-password">备份口令</label>
      <el-input
        id="backup-password"
        v-model="backupPassword"
        data-testid="backup-password"
        type="password"
        autocomplete="off"
        show-password
      />
      <label v-if="backupMode === 'import'" for="backup-file">PEM 备份文件</label>
      <input
        v-if="backupMode === 'import'"
        id="backup-file"
        data-testid="backup-file"
        type="file"
        accept=".pem,application/x-pem-file"
        @change="selectBackup"
      />
    </div>
    <template #footer>
      <el-button :disabled="backupSubmitting" @click="closeBackup">取消</el-button>
      <el-button
        data-testid="submit-backup"
        type="primary"
        :loading="backupSubmitting"
        :disabled="!backupPassword || (backupMode === 'import' && !backupFile)"
        @click="submitBackup"
        >{{ backupMode === 'export' ? '下载加密备份' : '恢复密钥环' }}</el-button
      >
    </template>
  </el-dialog>
</template>

<style scoped>
.me-page {
  display: grid;
  gap: 24px;
  width: 100%;
}

.me-profile-banner,
.me-card {
  border: 1px solid var(--cc-line);
  background: var(--cc-card);
  box-shadow: var(--cc-shadow);
}

.me-profile-banner {
  position: relative;
  display: flex;
  min-height: 116px;
  align-items: center;
  justify-content: space-between;
  gap: 28px;
  padding: 22px 26px;
  overflow: hidden;
  border-radius: 14px;
}

.me-profile-banner::before {
  position: absolute;
  top: 0;
  left: 0;
  width: 5px;
  height: 100%;
  background: var(--cc-primary);
  content: '';
}

.me-profile-identity,
.me-profile-meta,
.me-card-heading,
.me-action-row,
.danger-confirmation-title,
.danger-confirmation-actions,
.inline-confirmation,
.inline-confirmation > div {
  display: flex;
  align-items: center;
}

.me-profile-identity {
  min-width: 0;
  gap: 16px;
}

.me-avatar {
  display: grid;
  width: 58px;
  height: 58px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 14px;
  color: #fff;
  background: linear-gradient(145deg, var(--cc-primary), var(--cc-primary-dark));
  font-size: 25px;
  font-weight: 750;
}

.me-profile-identity h1 {
  margin: 3px 0 5px;
  color: var(--cc-primary-dark);
  font-size: 28px;
}

.me-profile-identity p:last-child {
  margin: 0;
  overflow: hidden;
  color: var(--cc-muted);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.me-profile-meta {
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 9px;
  color: var(--cc-muted);
  font-size: 12px;
}

.me-banner-error {
  position: absolute;
  right: 26px;
  bottom: 8px;
  width: auto;
  max-width: 440px;
  padding-block: 3px;
}

.me-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(390px, 0.92fr);
  gap: 22px;
  align-items: start;
}

.me-column {
  display: grid;
  gap: 22px;
}

.me-card {
  min-width: 0;
  padding: 22px;
  border-radius: 12px;
}

.me-card-heading {
  gap: 11px;
}

.me-card-heading-row {
  justify-content: space-between;
  gap: 16px;
}

.me-card-heading-row > .me-card-heading {
  min-width: 0;
}

.me-card-icon {
  display: grid;
  width: 38px;
  height: 38px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 9px;
  color: var(--cc-primary-dark);
  background: var(--cc-primary-light);
  font-size: 19px;
}

.me-section-number {
  display: block;
  margin-bottom: 2px;
  color: var(--cc-primary);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.16em;
}

.me-card h2 {
  margin: 0;
  color: var(--cc-primary-dark);
  font-size: 18px;
}

.me-form {
  display: grid;
  gap: 10px;
  margin-top: 20px;
}

.me-form label,
.danger-confirmation label {
  color: #344052;
  font-size: 12px;
  font-weight: 700;
}

.me-form small {
  margin-top: -4px;
  color: var(--cc-muted);
  font-size: 11px;
}

.me-form .el-button {
  width: max-content;
  min-width: 116px;
  margin-top: 4px;
}

.me-note {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  margin-top: 17px;
  padding: 11px 13px;
  border: 1px solid #dce8f5;
  border-radius: 8px;
  color: #496178;
  background: #f4f8fc;
  font-size: 11px;
  line-height: 1.65;
}

.me-note .el-icon {
  flex: 0 0 auto;
  margin-top: 2px;
  color: var(--cc-primary);
}

.me-note p {
  margin: 0;
}

.me-table-wrap {
  margin-top: 18px;
  overflow-x: auto;
  border: 1px solid var(--cc-line);
  border-radius: 9px;
}

.me-table {
  width: 100%;
  min-width: 620px;
  border-collapse: collapse;
  text-align: left;
}

.me-table th,
.me-table td {
  padding: 11px 12px;
  border-bottom: 1px solid #e8ecf1;
  color: #344052;
  font-size: 11px;
  vertical-align: middle;
}

.me-table th {
  color: #435063;
  background: #f5f7fa;
  font-weight: 750;
}

.me-table tbody tr:last-child td {
  border-bottom: 0;
}

.me-table tbody tr:hover {
  background: #f8fbff;
}

.me-table code {
  color: #334c6d;
  font-family: 'Cascadia Code', 'SFMono-Regular', Consolas, monospace;
  font-size: 10px;
}

.me-table td small {
  display: block;
  margin-top: 4px;
  color: var(--cc-muted);
  font-size: 9px;
  white-space: nowrap;
}

.sessions-table {
  min-width: 560px;
}

.me-action-row {
  flex-wrap: wrap;
  gap: 9px;
  margin-top: 17px;
}

.danger-confirmation {
  display: grid;
  gap: 12px;
  margin-top: 16px;
  padding: 15px;
  border: 1px solid #edb8b3;
  border-radius: 9px;
  background: #fff7f6;
}

.backup-form {
  display: grid;
  gap: 10px;
}

.backup-form p {
  margin: 0 0 4px;
  color: var(--cc-muted);
  font-size: 11px;
  line-height: 1.6;
}

.backup-form label {
  color: #344052;
  font-size: 12px;
  font-weight: 700;
}

.backup-form input[type='file'] {
  padding: 10px;
  border: 1px solid var(--cc-line);
  border-radius: 8px;
  background: #f8fafc;
}

.danger-confirmation-title {
  gap: 7px;
  color: #a72d24;
}

.danger-confirmation > p {
  margin: 0;
  color: #70423e;
  font-size: 11px;
  line-height: 1.65;
}

.danger-confirmation-actions {
  justify-content: flex-end;
  gap: 8px;
}

.inline-confirmation {
  justify-content: space-between;
  gap: 14px;
  margin-top: 14px;
  padding: 11px 12px;
  border: 1px solid #edb8b3;
  border-radius: 8px;
  color: #70423e;
  background: #fff7f6;
  font-size: 11px;
  line-height: 1.5;
}

.inline-confirmation > div {
  flex: 0 0 auto;
  gap: 7px;
}

.me-feedback {
  margin-top: 14px;
}

.quota-reset {
  color: var(--cc-muted);
  font-size: 10px;
  white-space: nowrap;
}

.quota-list {
  display: grid;
  gap: 18px;
  margin-top: 22px;
}

.quota-item {
  display: grid;
  gap: 9px;
}

.quota-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  color: #344052;
  font-size: 12px;
}

.quota-heading strong,
.quota-heading small {
  display: block;
}

.quota-heading small {
  margin-top: 3px;
  color: var(--cc-muted);
  font-size: 10px;
}

.quota-heading > span {
  color: var(--cc-primary-dark);
  font-weight: 750;
  white-space: nowrap;
}

.privacy-table {
  min-width: 540px;
}

.privacy-no,
.privacy-yes {
  font-weight: 700;
}

.privacy-no {
  color: #b5362d;
}

.privacy-yes {
  color: #986814;
}

.privacy-note {
  border-color: #d5e9dd;
  color: #356146;
  background: #f2faf5;
}

.privacy-note .el-icon {
  color: #1d8a4e;
}

.account-actions-card {
  border-color: #ead8d6;
}

.danger-note {
  border-color: #efdbd8;
  color: #70423e;
  background: #fff8f7;
}

.danger-note .el-icon {
  color: #c8382e;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

:deep(.el-input__wrapper) {
  min-height: 40px;
  border-radius: 8px;
  box-shadow: 0 0 0 1px var(--cc-line) inset;
}

:deep(.el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px #9eb5d2 inset;
}

:deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 2px var(--cc-primary) inset;
}

:deep(.el-alert) {
  margin-top: 16px;
}

:deep(.el-empty) {
  padding-block: 20px 8px;
}

@media (max-width: 1120px) {
  .me-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 820px) {
  .me-profile-banner,
  .me-profile-meta {
    align-items: flex-start;
  }

  .me-profile-banner {
    flex-direction: column;
  }

  .me-profile-meta {
    justify-content: flex-start;
  }

  .me-banner-error {
    position: static;
    max-width: none;
  }
}
</style>
