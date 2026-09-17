<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import { Lock, Message } from '@element-plus/icons-vue'
import type { FormInstance, FormRules } from 'element-plus'
import { useRoute, useRouter } from 'vue-router'

import { requestRegistrationCode } from '@/api/auth'
import { ApiError, messageForApiError } from '@/api/errors'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

type AuthMode = 'login' | 'register'

interface LoginForm {
  email: string
  password: string
}

interface RegisterForm extends LoginForm {
  verificationCode: string
  confirmPassword: string
}

const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{10,128}$/

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const security = useSecurityStore()

const mode = ref<AuthMode>('login')
const loginFormRef = ref<FormInstance>()
const registerFormRef = ref<FormInstance>()
const isSubmitting = ref(false)
const isSendingCode = ref(false)
const codeRequested = ref(false)
const pageError = ref('')
const pageNotice = ref('')

const loginForm = reactive<LoginForm>({ email: '', password: '' })
const registerForm = reactive<RegisterForm>({
  email: '',
  password: '',
  verificationCode: '',
  confirmPassword: '',
})

const emailRules = [
  { required: true, message: '请输入校园邮箱。', trigger: 'blur' },
  { type: 'email' as const, message: '请输入有效的邮箱地址。', trigger: ['blur', 'change'] },
  { max: 254, message: '邮箱地址不能超过 254 个字符。', trigger: 'blur' },
]

const loginRules: FormRules<LoginForm> = {
  email: emailRules,
  password: [
    { required: true, message: '请输入口令。', trigger: 'blur' },
    { max: 128, message: '口令不能超过 128 个字符。', trigger: 'blur' },
  ],
}

const registerRules: FormRules<RegisterForm> = {
  email: emailRules,
  verificationCode: [
    { required: true, message: '请输入邮箱验证码。', trigger: 'blur' },
    { pattern: /^\d{6}$/, message: '验证码应为 6 位数字。', trigger: ['blur', 'change'] },
  ],
  password: [
    { required: true, message: '请设置口令。', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (!PASSWORD_PATTERN.test(value)) {
          callback(new Error('口令需为 10–128 位，并包含大写字母、小写字母和数字。'))
        } else callback()
      },
      trigger: ['blur', 'change'],
    },
  ],
  confirmPassword: [
    { required: true, message: '请再次输入口令。', trigger: 'blur' },
    {
      validator: (_rule, value: string, callback) => {
        if (value !== registerForm.password) callback(new Error('两次输入的口令不一致。'))
        else callback()
      },
      trigger: ['blur', 'change'],
    },
  ],
}

const systemVersion = computed(() => security.systemStatus?.version ?? '版本未知')
const engineTone = computed<'success' | 'warning' | 'danger' | 'info'>(() => {
  if (!security.systemStatus) return 'info'
  if (security.systemStatus.engine === 'online') return 'success'
  if (security.systemStatus.engine === 'degraded') return 'warning'
  return 'danger'
})
const tlcpLabel = computed(() => {
  if (!security.systemStatus) return 'TLCP 状态未知'
  const labels = { online: 'TLCP 在线', offline: 'TLCP 离线', unknown: 'TLCP 状态未知' }
  return labels[security.systemStatus.tlcp]
})
const tlcpTone = computed<'success' | 'danger' | 'info'>(() => {
  if (security.systemStatus?.tlcp === 'online') return 'success'
  if (security.systemStatus?.tlcp === 'offline') return 'danger'
  return 'info'
})

function resetFeedback(): void {
  pageError.value = ''
  pageNotice.value = ''
}

function switchMode(nextMode: AuthMode): void {
  if (isSubmitting.value || isSendingCode.value || mode.value === nextMode) return
  resetFeedback()
  mode.value = nextMode
  nextTick(() => {
    loginFormRef.value?.clearValidate()
    registerFormRef.value?.clearValidate()
  })
}

function errorMessage(error: unknown, context: 'login' | 'register' | 'code'): string {
  if (!(error instanceof ApiError)) return messageForApiError('UNKNOWN_ERROR')
  if (error.status === 404 || error.status === 501) {
    return '认证服务暂未开放，请等待后端接口就绪后重试。'
  }
  if (context === 'login' && error.status === 429) {
    return '登录尝试次数过多，账号可能已暂时锁定，请 10 分钟后再试。'
  }
  if (context === 'code' && error.status === 429) {
    return '验证码请求过于频繁，请稍后再试。'
  }
  if (context === 'register' && error.status === 409) {
    return '该校园邮箱已注册或当前状态不允许注册。'
  }
  return error.message
}

function redirectAfterAuthentication(): string {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
  if (!redirect.startsWith('/') || redirect.startsWith('//') || redirect.startsWith('/login')) {
    return '/'
  }
  return redirect
}

async function submitLogin(): Promise<void> {
  if (!loginFormRef.value || isSubmitting.value) return
  resetFeedback()
  try {
    await loginFormRef.value.validate()
  } catch {
    return
  }

  isSubmitting.value = true
  try {
    await session.signIn({
      email: loginForm.email.trim().toLowerCase(),
      password: loginForm.password,
    })
    await router.replace(redirectAfterAuthentication())
  } catch (error) {
    pageError.value = errorMessage(error, 'login')
  } finally {
    isSubmitting.value = false
  }
}

async function sendRegistrationCode(): Promise<void> {
  if (!registerFormRef.value || isSendingCode.value) return
  resetFeedback()
  try {
    await registerFormRef.value.validateField('email')
  } catch {
    return
  }

  isSendingCode.value = true
  try {
    await requestRegistrationCode({ email: registerForm.email.trim().toLowerCase() })
    codeRequested.value = true
    pageNotice.value = '请求已受理。如邮箱可用，验证码将发送到该邮箱。'
  } catch (error) {
    pageError.value = errorMessage(error, 'code')
  } finally {
    isSendingCode.value = false
  }
}

async function submitRegistration(): Promise<void> {
  if (!registerFormRef.value || isSubmitting.value) return
  resetFeedback()
  try {
    await registerFormRef.value.validate()
  } catch {
    return
  }

  isSubmitting.value = true
  try {
    await session.signUp({
      email: registerForm.email.trim().toLowerCase(),
      password: registerForm.password,
      verification_code: registerForm.verificationCode,
    })
    await router.replace(redirectAfterAuthentication())
  } catch (error) {
    pageError.value = errorMessage(error, 'register')
  } finally {
    isSubmitting.value = false
  }
}

onMounted(() => security.loadSystemStatus())
</script>

<template>
  <main id="main-content" class="auth-page">
    <section class="auth-panel" aria-labelledby="auth-form-title">
      <header class="auth-panel-header">
        <div class="auth-brand-mark" aria-hidden="true">
          <el-icon><Lock /></el-icon>
        </div>
        <h1 id="auth-form-title">密信校园 CryptoCampus</h1>
        <p>
          {{
            mode === 'login'
              ? '你的文件、树洞与投票，都由国密守护'
              : '验证校园邮箱，建立你的安全身份'
          }}
        </p>
      </header>

      <div class="auth-mode-switch" role="group" aria-label="认证方式">
        <button
          type="button"
          :aria-pressed="mode === 'login'"
          :class="{ active: mode === 'login' }"
          @click="switchMode('login')"
        >
          登录
        </button>
        <button
          type="button"
          :aria-pressed="mode === 'register'"
          :class="{ active: mode === 'register' }"
          @click="switchMode('register')"
        >
          注册
        </button>
      </div>

      <el-alert
        v-if="pageError"
        class="auth-feedback"
        :title="pageError"
        type="error"
        :closable="false"
        show-icon
      />
      <el-alert
        v-else-if="pageNotice"
        class="auth-feedback"
        :title="pageNotice"
        type="success"
        :closable="false"
        show-icon
      />

      <el-form
        v-if="mode === 'login'"
        ref="loginFormRef"
        class="auth-form"
        data-testid="login-form"
        :model="loginForm"
        :rules="loginRules"
        label-position="top"
        hide-required-asterisk
        @submit.prevent="submitLogin"
      >
        <el-form-item label="校园邮箱" prop="email">
          <el-input
            v-model="loginForm.email"
            data-testid="login-email"
            name="email"
            type="email"
            autocomplete="username"
            inputmode="email"
            placeholder="name@example.edu.cn"
            :prefix-icon="Message"
            clearable
          />
        </el-form-item>
        <el-form-item label="口令" prop="password">
          <el-input
            v-model="loginForm.password"
            data-testid="login-password"
            name="password"
            type="password"
            autocomplete="current-password"
            placeholder="请输入口令"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <el-button
          class="auth-submit"
          data-testid="login-submit"
          native-type="submit"
          type="primary"
          size="large"
          :loading="isSubmitting"
        >
          登录
        </el-button>
      </el-form>

      <el-form
        v-else
        ref="registerFormRef"
        class="auth-form"
        data-testid="register-form"
        :model="registerForm"
        :rules="registerRules"
        label-position="top"
        hide-required-asterisk
        @submit.prevent="submitRegistration"
      >
        <el-form-item label="校园邮箱" prop="email">
          <el-input
            v-model="registerForm.email"
            data-testid="register-email"
            name="email"
            type="email"
            autocomplete="username"
            inputmode="email"
            placeholder="name@example.edu.cn"
            :prefix-icon="Message"
            clearable
          />
        </el-form-item>
        <el-form-item label="邮箱验证码" prop="verificationCode">
          <div class="verification-row">
            <el-input
              v-model="registerForm.verificationCode"
              data-testid="register-code"
              name="verification-code"
              autocomplete="one-time-code"
              inputmode="numeric"
              maxlength="6"
              placeholder="6 位数字"
            />
            <el-button
              data-testid="send-code"
              type="primary"
              plain
              :loading="isSendingCode"
              @click="sendRegistrationCode"
            >
              {{ codeRequested ? '重新发送' : '获取验证码' }}
            </el-button>
          </div>
        </el-form-item>
        <el-form-item label="设置口令" prop="password">
          <el-input
            v-model="registerForm.password"
            data-testid="register-password"
            name="new-password"
            type="password"
            autocomplete="new-password"
            placeholder="10–128 位，含大小写字母和数字"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <el-form-item label="确认口令" prop="confirmPassword">
          <el-input
            v-model="registerForm.confirmPassword"
            data-testid="register-confirm-password"
            name="confirm-password"
            type="password"
            autocomplete="new-password"
            placeholder="再次输入口令"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <p class="password-guidance">口令仅通过安全请求提交；页面不会记录、回显或持久化。</p>
        <el-button
          class="auth-submit"
          data-testid="register-submit"
          native-type="submit"
          type="primary"
          size="large"
          :loading="isSubmitting"
        >
          注册并创建安全身份
        </el-button>
      </el-form>

      <footer class="auth-status" aria-live="polite">
        <p>注册后由平台生成 SM2 密钥环与数字证书</p>
        <div>
          <span
            class="status-dot"
            :class="{ online: security.engineOnline }"
            aria-hidden="true"
          ></span>
          <span>{{ security.statusLabel }}</span>
          <el-tag size="small" effect="light" :type="engineTone">{{ systemVersion }}</el-tag>
        </div>
        <el-tag size="small" effect="plain" :type="tlcpTone">{{ tlcpLabel }}</el-tag>
      </footer>
    </section>
  </main>
</template>
