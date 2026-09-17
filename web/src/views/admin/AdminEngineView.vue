<script setup lang="ts">
/* global crypto, document, URL */
import { computed, onMounted, reactive, ref, shallowRef } from 'vue'
import { Cpu, Download, Lock, Refresh, UserFilled, WarningFilled } from '@element-plus/icons-vue'

import {
  destroyDrop,
  exportAdminAudit,
  flagVoteForAudit,
  getEngineDetails,
  listAdminUsers,
  reloadPqcProvider,
  resetUserQuotas,
  updateUserRole,
  updateUserStatus,
  withdrawHolePost,
  type SystemStatus,
  type User,
  type UserPage,
} from '@/api/admin'
import { ApiError, messageForApiError } from '@/api/errors'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const status = shallowRef<SystemStatus | null>(null)
const loading = ref(false)
const reloading = ref(false)
const errorMessage = ref('')
const users = shallowRef<UserPage | null>(null)
const usersLoading = ref(false)
const managementLoading = ref(false)
const managementMessage = ref('')
const userAction = reactive({ userId: '', role: 'student', status: 'active', reason: '' })
const governance = reactive({ kind: 'hole', target: '', reason: '' })
const providers = computed(() => Object.entries(status.value?.providers ?? {}))

function safeError(error: unknown): string {
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

async function load(): Promise<void> {
  if (!session.accessToken || !session.isPrivileged || loading.value || reloading.value) return
  loading.value = true
  errorMessage.value = ''
  try {
    status.value = await getEngineDetails(session.accessToken)
  } catch (error) {
    status.value = null
    errorMessage.value = safeError(error)
  } finally {
    loading.value = false
  }
}

async function reloadProvider(): Promise<void> {
  if (!session.accessToken || !session.isPrivileged || loading.value || reloading.value) return
  reloading.value = true
  errorMessage.value = ''
  try {
    status.value = await reloadPqcProvider(session.accessToken, crypto.randomUUID())
  } catch (error) {
    errorMessage.value = safeError(error)
  } finally {
    reloading.value = false
  }
}

async function loadUsers(page = 1): Promise<void> {
  if (!session.accessToken || usersLoading.value) return
  usersLoading.value = true
  managementMessage.value = ''
  try {
    users.value = await listAdminUsers(session.accessToken, page)
  } catch (error) {
    managementMessage.value = safeError(error)
  } finally {
    usersLoading.value = false
  }
}

function replaceUser(updated: User): void {
  if (!users.value) return
  users.value = {
    ...users.value,
    items: users.value.items.map((item) => (item.id === updated.id ? updated : item)),
  }
}

async function submitUserAction(kind: 'status' | 'role' | 'quota'): Promise<void> {
  if (!session.accessToken || !userAction.userId || managementLoading.value) return
  if (kind !== 'quota' && !userAction.reason.trim()) {
    managementMessage.value = '治理操作必须填写原因。'
    return
  }
  managementLoading.value = true
  managementMessage.value = ''
  try {
    if (kind === 'status') {
      replaceUser(
        await updateUserStatus(
          userAction.userId,
          { status: userAction.status as 'active' | 'frozen', reason: userAction.reason.trim() },
          session.accessToken,
        ),
      )
    } else if (kind === 'role') {
      replaceUser(
        await updateUserRole(
          userAction.userId,
          {
            role: userAction.role as 'student' | 'admin' | 'teacher',
            reason: userAction.reason.trim(),
          },
          session.accessToken,
        ),
      )
    } else {
      await resetUserQuotas(userAction.userId, session.accessToken, crypto.randomUUID())
    }
    managementMessage.value = '治理操作已提交并由服务端记录审计日志。'
  } catch (error) {
    managementMessage.value = safeError(error)
  } finally {
    managementLoading.value = false
  }
}

async function submitGovernance(): Promise<void> {
  if (!session.accessToken || !governance.target.trim() || managementLoading.value) return
  if (governance.kind !== 'drop' && !governance.reason.trim()) {
    managementMessage.value = '治理操作必须填写原因。'
    return
  }
  managementLoading.value = true
  managementMessage.value = ''
  try {
    if (governance.kind === 'hole') {
      await withdrawHolePost(
        governance.target.trim(),
        governance.reason.trim(),
        session.accessToken,
      )
    } else if (governance.kind === 'drop') {
      await destroyDrop(governance.target.trim(), session.accessToken)
    } else {
      await flagVoteForAudit(
        governance.target.trim(),
        governance.reason.trim(),
        session.accessToken,
      )
    }
    managementMessage.value = '内容治理操作已完成。'
    governance.target = ''
    governance.reason = ''
  } catch (error) {
    managementMessage.value = safeError(error)
  } finally {
    managementLoading.value = false
  }
}

async function downloadAudit(format: 'csv' | 'json'): Promise<void> {
  if (!session.accessToken || managementLoading.value) return
  managementLoading.value = true
  managementMessage.value = ''
  try {
    const report = await exportAdminAudit(format, session.accessToken)
    const url = URL.createObjectURL(report)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `cryptocampus-audit.${format}`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    managementMessage.value = safeError(error)
  } finally {
    managementLoading.value = false
  }
}

onMounted(() => void load())
</script>

<template>
  <section class="engine-page" aria-labelledby="engine-title">
    <header>
      <div>
        <p class="eyebrow">管理员与教师 · FR-10</p>
        <h1 id="engine-title">密码引擎与 Provider</h1>
        <p>只展示能力与健康状态；任何配置密钥、私钥和运行时秘密均不得返回页面。</p>
      </div>
      <el-button :icon="Refresh" :loading="loading" :disabled="reloading" @click="load"
        >刷新状态</el-button
      >
    </header>
    <el-alert
      v-if="errorMessage"
      :title="errorMessage"
      type="warning"
      :closable="false"
      show-icon
    />
    <div class="engine-grid">
      <section class="status-card">
        <div class="card-title">
          <div>
            <p class="eyebrow">核心服务</p>
            <h2>运行状态</h2>
          </div>
          <el-icon><Cpu /></el-icon>
        </div>
        <el-skeleton v-if="loading" :rows="5" animated />
        <template v-else-if="status">
          <div class="engine-state" :class="status.engine">
            <span />
            <div>
              <strong>{{
                status.engine === 'online'
                  ? '引擎在线'
                  : status.engine === 'degraded'
                    ? '引擎降级'
                    : '引擎离线'
              }}</strong
              ><small>openHiTLS {{ status.version }}</small>
            </div>
          </div>
          <dl>
            <div>
              <dt>API</dt>
              <dd>{{ status.api }}</dd>
            </div>
            <div>
              <dt>TLCP 网关</dt>
              <dd>{{ status.tlcp }}</dd>
            </div>
          </dl>
        </template>
        <el-empty v-else description="暂无引擎状态" />
      </section>
      <section class="provider-card">
        <div class="card-title">
          <div>
            <p class="eyebrow">算法敏捷</p>
            <h2>Provider 能力</h2>
          </div>
          <el-icon><Lock /></el-icon>
        </div>
        <div v-if="providers.length" class="provider-list">
          <div v-for="[name, enabled] in providers" :key="name">
            <span :class="{ enabled }" /><strong>{{ name }}</strong
            ><small>{{ enabled ? '可用' : '不可用' }}</small>
          </div>
        </div>
        <el-empty v-else description="暂无 Provider 信息" />
        <el-button
          type="primary"
          :icon="Refresh"
          :loading="reloading"
          :disabled="!status || loading"
          @click="reloadProvider"
          >重新加载 PQC Provider</el-button
        >
        <p v-if="status?.providers.pqc === false">
          当前运行镜像尚未把 ML-KEM/ML-DSA 接入业务 bridge；仅重新加载页面或 Provider
          不能补齐该能力。
        </p>
        <p v-else>重载动作由后端调用稳定 bridge；页面只发送幂等请求，不上传配置或密钥。</p>
      </section>
    </div>
    <section class="management-card" aria-labelledby="user-management-title">
      <div class="card-title">
        <div>
          <p class="eyebrow">账号治理</p>
          <h2 id="user-management-title">用户、角色与额度</h2>
        </div>
        <el-button :icon="UserFilled" :loading="usersLoading" @click="loadUsers()"
          >加载用户</el-button
        >
      </div>
      <el-skeleton v-if="usersLoading" :rows="5" animated />
      <div v-else-if="users?.items.length" class="admin-table-wrap">
        <table class="admin-table">
          <thead>
            <tr>
              <th>账号</th>
              <th>角色</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users.items" :key="user.id">
              <td>
                <strong>{{ user.email }}</strong
                ><small>{{ user.id }}</small>
              </td>
              <td>{{ user.role }}</td>
              <td>{{ user.status }}</td>
              <td><el-button size="small" @click="userAction.userId = user.id">选择</el-button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <el-empty v-else description="点击“加载用户”读取受权限控制的账号列表" />

      <div class="management-form">
        <el-input v-model="userAction.userId" placeholder="用户 UUID" />
        <el-select v-model="userAction.status" aria-label="账号状态">
          <el-option label="正常" value="active" /><el-option label="冻结" value="frozen" />
        </el-select>
        <el-select v-model="userAction.role" aria-label="账号角色">
          <el-option label="学生" value="student" /><el-option
            label="教师"
            value="teacher"
          /><el-option label="管理员" value="admin" />
        </el-select>
        <el-input v-model="userAction.reason" placeholder="操作原因（必填）" />
        <div class="form-actions">
          <el-button :loading="managementLoading" @click="submitUserAction('status')"
            >更新状态</el-button
          >
          <el-button :loading="managementLoading" @click="submitUserAction('role')"
            >更新角色</el-button
          >
          <el-button :loading="managementLoading" @click="submitUserAction('quota')"
            >重置额度</el-button
          >
        </div>
      </div>
    </section>

    <section class="management-card" aria-labelledby="governance-title">
      <div class="card-title">
        <div>
          <p class="eyebrow">最小权限治理</p>
          <h2 id="governance-title">内容治理与审计导出</h2>
        </div>
        <div class="form-actions">
          <el-button :icon="Download" :loading="managementLoading" @click="downloadAudit('csv')"
            >导出 CSV</el-button
          >
          <el-button :icon="Download" :loading="managementLoading" @click="downloadAudit('json')"
            >导出 JSON</el-button
          >
        </div>
      </div>
      <div class="governance-form">
        <el-select v-model="governance.kind" aria-label="治理对象">
          <el-option label="撤下树洞帖子" value="hole" />
          <el-option label="销毁密信密文" value="drop" />
          <el-option label="标记投票审计" value="vote" />
        </el-select>
        <el-input
          v-model="governance.target"
          :placeholder="governance.kind === 'drop' ? '提取码' : '对象 UUID'"
        />
        <el-input v-model="governance.reason" placeholder="操作原因（销毁密信除外）" />
        <el-button type="danger" plain :loading="managementLoading" @click="submitGovernance"
          >执行治理操作</el-button
        >
      </div>
      <el-alert
        v-if="managementMessage"
        :title="managementMessage"
        type="info"
        :closable="false"
        show-icon
      />
    </section>
    <section class="boundary">
      <el-icon><WarningFilled /></el-icon>
      <div>
        <strong>管理权限不是解密权限</strong>
        <p>
          管理员可以观察引擎、重载 Provider
          和执行治理操作，但不能查看或解密用户密信、匿名帖子归属与选票归属。
        </p>
      </div>
    </section>
  </section>
</template>

<style scoped>
.engine-page {
  display: grid;
  gap: 16px;
}
.engine-page > header,
.card-title,
.engine-state,
.boundary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}
.engine-page > header {
  align-items: flex-start;
}
.engine-page h1 {
  margin: 4px 0 6px;
  color: var(--cc-primary-dark);
  font-size: 34px;
}
.engine-page header p:not(.eyebrow),
.provider-card > p,
.boundary p {
  margin: 0;
  color: var(--cc-muted);
  font-size: 10px;
  line-height: 1.55;
}
.eyebrow {
  margin: 0;
  color: var(--cc-primary);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.08em;
}
.engine-grid {
  display: grid;
  grid-template-columns: 0.9fr 1.1fr;
  gap: 16px;
}
.status-card,
.provider-card,
.management-card,
.boundary {
  padding: 20px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.management-card {
  min-width: 0;
}
.admin-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--cc-line);
  border-radius: 9px;
}
.admin-table {
  width: 100%;
  min-width: 720px;
  border-collapse: collapse;
  text-align: left;
}
.admin-table th,
.admin-table td {
  padding: 11px 12px;
  border-bottom: 1px solid #e8ecf1;
  font-size: 11px;
}
.admin-table th {
  color: #435063;
  background: #f5f7fa;
}
.admin-table small {
  display: block;
  margin-top: 3px;
  color: var(--cc-muted);
  font-family: 'Cascadia Code', Consolas, monospace;
}
.management-form,
.governance-form,
.form-actions {
  display: flex;
  align-items: center;
  gap: 9px;
}
.management-form,
.governance-form {
  margin-top: 14px;
}
.management-form > .el-input,
.governance-form > .el-input {
  flex: 1;
}
.management-form > .el-select,
.governance-form > .el-select {
  width: 150px;
}
.form-actions {
  flex: 0 0 auto;
  flex-wrap: wrap;
}
.card-title h2 {
  margin: 4px 0 14px;
  color: var(--cc-primary-dark);
}
.card-title > .el-icon {
  font-size: 28px;
  color: var(--cc-primary);
}
.engine-state {
  justify-content: flex-start;
  padding: 18px;
  background: #f4f7fb;
}
.engine-state > span,
.provider-list span {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #c94842;
  box-shadow: 0 0 0 4px #fae8e6;
}
.engine-state.online > span,
.provider-list span.enabled {
  background: #2e8b57;
  box-shadow: 0 0 0 4px #def2e6;
}
.engine-state strong,
.engine-state small {
  display: block;
}
.engine-state small {
  margin-top: 4px;
  color: var(--cc-muted);
}
dl {
  display: grid;
  margin: 16px 0 0;
  border-top: 1px solid #e5eaf0;
}
dl div {
  display: flex;
  justify-content: space-between;
  padding: 11px 0;
  border-bottom: 1px solid #e5eaf0;
}
dd {
  margin: 0;
  font-weight: 800;
}
.provider-list {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 16px;
}
.provider-list > div {
  display: grid;
  grid-template-columns: 14px 1fr auto;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: #f7f9fc;
}
.provider-list small {
  color: var(--cc-muted);
}
.provider-card > p {
  margin-top: 10px;
}
.boundary {
  justify-content: flex-start;
  color: #665327;
  background: #fff9ea;
}
.boundary > .el-icon {
  font-size: 24px;
}
@media (max-width: 800px) {
  .engine-grid {
    grid-template-columns: 1fr;
  }
  .engine-page > header {
    flex-direction: column;
    align-items: stretch;
  }
  .management-form,
  .governance-form {
    align-items: stretch;
    flex-direction: column;
  }
  .management-form > .el-select,
  .governance-form > .el-select {
    width: 100%;
  }
}
</style>
