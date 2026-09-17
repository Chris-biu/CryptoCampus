<script setup lang="ts">
import { computed, onMounted, shallowRef } from 'vue'
import {
  ChatDotRound,
  ChatLineRound,
  DocumentChecked,
  Histogram,
  Key,
  Promotion,
  Refresh,
} from '@element-plus/icons-vue'
import type { Component } from 'vue'

import { ApiError, messageForApiError } from '@/api/errors'
import { getKeyring, type KeyringSummary } from '@/api/me'
import { useSecurityStore } from '@/stores/security'
import { useSessionStore } from '@/stores/session'

interface ServiceEntry {
  title: string
  description: string
  routeName: string
  icon: Component
  tags: ReadonlyArray<string>
  advanced?: boolean
}

const services: ReadonlyArray<ServiceEntry> = [
  {
    title: '密信快传',
    description: '加密便签或文件，通过链接与提取码安全分享。',
    routeName: 'drop-create',
    icon: Promotion,
    tags: ['数字信封', 'SM4 + SM2'],
  },
  {
    title: '匿名树洞',
    description: '用一次性匿名凭证发布内容，同时保留公开验证能力。',
    routeName: 'hole',
    icon: ChatDotRound,
    tags: ['盲签名', '可验证匿名'],
  },
  {
    title: '匿名投票',
    description: '支持一人一票的匿名参与和防篡改结果验证。',
    routeName: 'vote',
    icon: Histogram,
    tags: ['一人一票', '防重放'],
  },
  {
    title: '文件验真',
    description: '对校园证明与文件进行电子签章和五步验真。',
    routeName: 'verify',
    icon: DocumentChecked,
    tags: ['SM2 签名', '证书链'],
  },
  {
    title: '安全聊天',
    description: '课程进阶入口，用于展示加密会话与消息签名。',
    routeName: 'chat',
    icon: ChatLineRound,
    tags: ['ECDH', '进阶选做'],
    advanced: true,
  },
  {
    title: '我的密钥环',
    description: '查看身份密钥、平台证书及抗量子密钥摘要。',
    routeName: 'me',
    icon: Key,
    tags: ['SM2 身份', 'ML-KEM'],
  },
]

const session = useSessionStore()
const security = useSecurityStore()
const keyring = shallowRef<KeyringSummary | null>(null)
const isKeyringLoading = shallowRef(false)
const keyringError = shallowRef('')

const providerEntries = computed(() => Object.entries(security.systemStatus?.providers ?? {}))
const overallStatus = computed(() => {
  if (security.isLoading) return { label: '正在检测', type: 'info' as const }
  if (security.isUnavailable) return { label: '状态不可用', type: 'warning' as const }
  if (security.systemStatus?.engine === 'online') {
    return { label: '安全服务在线', type: 'success' as const }
  }
  if (security.systemStatus?.engine === 'degraded') {
    return { label: '安全服务降级', type: 'warning' as const }
  }
  return { label: '安全服务离线', type: 'danger' as const }
})

function serviceStatus(service: ServiceEntry): {
  label: string
  type: 'success' | 'warning' | 'info' | 'danger'
} {
  if (service.advanced) return { label: '进阶入口', type: 'info' }
  if (security.isLoading) return { label: '检测中', type: 'info' }
  if (security.isUnavailable || !security.systemStatus)
    return { label: '状态未知', type: 'warning' }
  if (security.systemStatus.engine === 'online') return { label: '入口可访问', type: 'success' }
  if (security.systemStatus.engine === 'degraded') return { label: '引擎降级', type: 'warning' }
  return { label: '引擎离线', type: 'danger' }
}

function kindLabel(kind: KeyringSummary['items'][number]['kind']): string {
  const labels = {
    sm2_identity: '身份签名密钥',
    certificate: '身份证书',
    ml_kem: '抗量子封装密钥',
  } as const
  return labels[kind]
}

function keyStatus(status: KeyringSummary['items'][number]['status']): {
  label: string
  type: 'success' | 'warning' | 'info' | 'danger'
} {
  const statuses = {
    active: { label: '已激活', type: 'success' as const },
    expired: { label: '已过期', type: 'warning' as const },
    revoked: { label: '已吊销', type: 'danger' as const },
    unavailable: { label: '不可用', type: 'info' as const },
  }
  return statuses[status]
}

function formatExpiry(value: string | null | undefined): string {
  if (!value) return '未提供'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '未提供'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date)
}

async function loadKeyring(): Promise<void> {
  if (!session.accessToken || isKeyringLoading.value) return
  isKeyringLoading.value = true
  keyringError.value = ''
  try {
    keyring.value = await getKeyring(session.accessToken)
  } catch (error) {
    keyring.value = null
    if (error instanceof ApiError && (error.status === 404 || error.status === 501)) {
      keyringError.value = '密钥环服务暂未开放。'
    } else {
      keyringError.value =
        error instanceof ApiError
          ? messageForApiError(error.code, error.status)
          : messageForApiError('UNKNOWN_ERROR')
    }
  } finally {
    isKeyringLoading.value = false
  }
}

async function refreshDashboard(): Promise<void> {
  await Promise.allSettled([security.loadSystemStatus(true), loadKeyring()])
}

onMounted(() => void loadKeyring())
</script>

<template>
  <section class="home-dashboard" aria-labelledby="home-title">
    <div class="page-heading home-heading">
      <div>
        <p class="eyebrow">校园安全服务</p>
        <h1 id="home-title">服务大厅</h1>
        <p>选择服务开始使用；密码能力均由后端 openHiTLS 引擎提供。</p>
      </div>
      <div class="home-heading-actions">
        <el-tag :type="overallStatus.type" effect="light" round>{{ overallStatus.label }}</el-tag>
        <el-button :icon="Refresh" :loading="security.isLoading" @click="refreshDashboard">
          刷新状态
        </el-button>
      </div>
    </div>

    <div class="service-grid" aria-label="六大服务入口">
      <RouterLink
        v-for="service in services"
        :key="service.routeName"
        class="service-card"
        :to="{ name: service.routeName }"
      >
        <div class="service-card-header">
          <span class="service-icon" aria-hidden="true">
            <el-icon><component :is="service.icon" /></el-icon>
          </span>
          <el-tag :type="serviceStatus(service).type" effect="plain" size="small" round>
            {{ serviceStatus(service).label }}
          </el-tag>
        </div>
        <strong>{{ service.title }}</strong>
        <span class="service-description">{{ service.description }}</span>
        <div class="service-tags" aria-label="相关密码能力">
          <span v-for="tag in service.tags" :key="tag">{{ tag }}</span>
        </div>
      </RouterLink>
    </div>

    <section class="home-section" aria-labelledby="security-overview-title">
      <div class="home-section-heading">
        <div>
          <p class="eyebrow">实时状态</p>
          <h2 id="security-overview-title">全局安全状态</h2>
        </div>
        <span>以服务端最近一次检测结果为准</span>
      </div>

      <el-skeleton v-if="security.isLoading && !security.systemStatus" :rows="2" animated />
      <el-alert
        v-else-if="security.isUnavailable"
        title="系统状态暂时不可用"
        description="无法连接状态接口；业务页面不会显示伪造的在线结果。"
        type="warning"
        :closable="false"
        show-icon
      />
      <div v-else class="security-status-grid">
        <article class="security-status-card">
          <span>密码引擎</span>
          <strong>{{ security.statusLabel }}</strong>
          <small>{{ security.systemStatus?.version || '版本未知' }}</small>
        </article>
        <article class="security-status-card">
          <span>TLCP 信道</span>
          <strong>{{
            security.systemStatus?.tlcp === 'online'
              ? '在线'
              : security.systemStatus?.tlcp === 'offline'
                ? '离线'
                : '未知'
          }}</strong>
          <small>实际连接状态由后端探测</small>
        </article>
        <article class="security-status-card pqc-status-card">
          <span>全局抗量子模式</span>
          <strong>{{
            security.pqcEnabled === null ? '状态未知' : security.pqcEnabled ? '已开启' : '未开启'
          }}</strong>
          <small>{{
            security.pqcEnabled ? '业务可请求混合密码能力' : '业务使用课程基线国密能力'
          }}</small>
        </article>
      </div>

      <div v-if="providerEntries.length" class="provider-list" aria-label="Provider 能力状态">
        <span v-for="[name, enabled] in providerEntries" :key="name">
          <span class="status-dot" :class="{ online: enabled }" />
          {{ name }}：{{ enabled ? '可用' : '不可用' }}
        </span>
      </div>
    </section>

    <section class="home-section keyring-section" aria-labelledby="keyring-title">
      <div class="home-section-heading">
        <div>
          <p class="eyebrow">个人密钥环</p>
          <h2 id="keyring-title">密钥与证书摘要</h2>
        </div>
        <span>仅展示后端返回的脱敏指纹，不展示私钥</span>
      </div>

      <el-skeleton v-if="isKeyringLoading" :rows="3" animated />
      <el-alert
        v-else-if="keyringError"
        title="无法读取密钥环"
        :description="keyringError"
        type="warning"
        :closable="false"
        show-icon
      />
      <el-empty
        v-else-if="keyring && keyring.items.length === 0"
        description="当前账号尚无可展示的密钥或证书"
        :image-size="72"
      />
      <div v-else-if="keyring" class="keyring-table-wrap">
        <table class="keyring-table">
          <thead>
            <tr>
              <th scope="col">密钥</th>
              <th scope="col">算法</th>
              <th scope="col">脱敏指纹</th>
              <th scope="col">状态</th>
              <th scope="col">有效期</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in keyring.items" :key="`${item.kind}-${item.fingerprint}`">
              <td>{{ kindLabel(item.kind) }}</td>
              <td>{{ item.algorithm }}</td>
              <td>
                <code>{{ item.fingerprint }}</code>
              </td>
              <td>
                <el-tag :type="keyStatus(item.status).type" effect="light" size="small">
                  {{ keyStatus(item.status).label }}
                </el-tag>
              </td>
              <td>{{ formatExpiry(item.expires_at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </section>
</template>
