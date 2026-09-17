<script setup lang="ts">
/* global crypto, document, URL, Blob */
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from 'vue'
import {
  Check,
  Download,
  Histogram,
  Lock,
  Plus,
  Refresh,
  WarningFilled,
} from '@element-plus/icons-vue'

import { ApiError, messageForApiError } from '@/api/errors'
import {
  createVote,
  createVoteCommitment,
  exportVoteAudit,
  getVoteResults,
  issueVoteCredential,
  listVotes,
  submitBallot,
  verifyVoteResult,
  type SignatureVerification,
  type VotePage,
  type VoteResult,
} from '@/api/votes'
import { acquireCredential, hasCredentialProvider } from '@/security/credential-provider'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const votes = shallowRef<VotePage | null>(null)
const selectedVoteId = ref('')
const selectedOptionId = ref('')
const result = shallowRef<VoteResult | null>(null)
const verification = shallowRef<SignatureVerification | null>(null)
const loading = ref(false)
const resultLoading = ref(false)
const actionLoading = ref(false)
const ballotSubmitting = ref(false)
const ballotFeedback = ref('')
const errorMessage = ref('')
const createOpen = ref(false)
const createForm = reactive({ title: '', options: '赞成\n反对', scope: 'public', closesAt: '' })

let selectionRevision = 0
onBeforeUnmount(() => {
  selectionRevision += 1
})

const selectedVote = computed(
  () => votes.value?.items.find((vote) => vote.id === selectedVoteId.value) ?? null,
)
const auditReady = computed(() => selectedVote.value?.status === 'published')
const maxCount = computed(() => Math.max(1, ...Object.values(result.value?.counts ?? {})))
const credentialProviderReady = computed(() => hasCredentialProvider())

function safeError(error: unknown): string {
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

async function loadVotes(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    votes.value = await listVotes()
    const nextId = votes.value.items.some((vote) => vote.id === selectedVoteId.value)
      ? selectedVoteId.value
      : (votes.value.items[0]?.id ?? '')
    await selectVote(nextId)
  } catch (error) {
    votes.value = null
    await selectVote('')
    errorMessage.value = safeError(error)
  } finally {
    loading.value = false
  }
}

async function selectVote(id: string): Promise<void> {
  const revision = ++selectionRevision
  selectedVoteId.value = id
  errorMessage.value = ''
  selectedOptionId.value = ''
  result.value = null
  verification.value = null
  resultLoading.value = Boolean(id)
  if (!id) return
  try {
    const response = await getVoteResults(id)
    if (revision !== selectionRevision) return
    if (response.vote_id !== id) throw new Error('Vote result mismatch')
    result.value = response
  } catch (error) {
    if (revision === selectionRevision && !(error instanceof ApiError && error.status === 404)) {
      errorMessage.value = safeError(error)
    }
  } finally {
    if (revision === selectionRevision) resultLoading.value = false
  }
}

async function verifyResult(): Promise<void> {
  if (!selectedVoteId.value || actionLoading.value) return
  const id = selectedVoteId.value
  const revision = selectionRevision
  verification.value = null
  actionLoading.value = true
  errorMessage.value = ''
  try {
    const response = await verifyVoteResult(id)
    if (revision === selectionRevision) verification.value = response
  } catch (error) {
    if (revision === selectionRevision) errorMessage.value = safeError(error)
  } finally {
    actionLoading.value = false
  }
}

async function downloadAudit(): Promise<void> {
  if (!selectedVoteId.value || actionLoading.value || !auditReady.value) return
  const id = selectedVoteId.value
  actionLoading.value = true
  errorMessage.value = ''
  try {
    const report = await exportVoteAudit(id)
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `vote-${id}-audit.json`
    anchor.click()
    URL.revokeObjectURL(url)
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError && error.status === 409
        ? '投票尚未完成最终结算，暂不能导出匿名审计；请稍后刷新投票状态。'
        : safeError(error)
  } finally {
    actionLoading.value = false
  }
}

async function submitCreate(): Promise<void> {
  if (!session.accessToken || actionLoading.value) return
  if (!createForm.title.trim() || createForm.title.trim().length > 200) {
    errorMessage.value = '请填写 1–200 字的投票议题。'
    return
  }
  const options = createForm.options
    .split('\n')
    .map((label) => label.trim())
    .filter(Boolean)
  if (options.length < 2 || options.length > 20 || options.some((label) => label.length > 100)) {
    errorMessage.value = '请填写 2–20 个选项，每项最多 100 字。'
    return
  }
  const closesAt = new Date(createForm.closesAt)
  if (!Number.isFinite(closesAt.getTime()) || closesAt.getTime() <= Date.now()) {
    errorMessage.value = '请选择有效的未来截止时间。'
    return
  }
  actionLoading.value = true
  errorMessage.value = ''
  try {
    const created = await createVote(
      {
        title: createForm.title.trim(),
        options: options.map((label) => ({ label })),
        scope: createForm.scope as 'public' | 'class' | 'group',
        closes_at: closesAt.toISOString(),
      },
      session.accessToken,
      crypto.randomUUID(),
    )
    createOpen.value = false
    await loadVotes()
    await selectVote(created.id)
  } catch (error) {
    errorMessage.value = safeError(error)
  } finally {
    actionLoading.value = false
  }
}

async function submitAnonymousVote(): Promise<void> {
  if (
    !session.accessToken ||
    !selectedVote.value ||
    !selectedOptionId.value ||
    ballotSubmitting.value
  )
    return

  const vote = selectedVote.value
  ballotSubmitting.value = true
  ballotFeedback.value = ''
  errorMessage.value = ''
  try {
    const credential = await acquireCredential(
      'vote_ballot',
      vote.id,
      (blindedMessage) =>
        issueVoteCredential(
          vote.id,
          { service: 'vote_ballot', period: vote.id, blinded_message: blindedMessage },
          session.accessToken!,
          crypto.randomUUID(),
        ),
      () => createVoteCommitment(vote.id, session.accessToken!),
      selectedOptionId.value,
    )
    await submitBallot(
      vote.id,
      { option_id: selectedOptionId.value, credential },
      crypto.randomUUID(),
    )
    ballotFeedback.value = '匿名选票已接收。页面未保存凭证、盲化因子或身份关联。'
    selectedOptionId.value = ''
    await selectVote(vote.id)
  } catch (error) {
    errorMessage.value = safeError(error)
  } finally {
    ballotSubmitting.value = false
  }
}

onMounted(() => void loadVotes())
</script>

<template>
  <section class="vote-page" aria-labelledby="vote-title">
    <header class="vote-heading">
      <div>
        <p class="eyebrow">匿名选择 · 公开计票</p>
        <h1 id="vote-title">匿名投票</h1>
        <p>记名签发只证明投票资格；匿名选票与身份分离，结果由计票台签名。</p>
      </div>
      <div>
        <el-button :icon="Refresh" :loading="loading" @click="loadVotes">刷新</el-button>
        <el-button
          v-if="session.isAuthenticated"
          type="primary"
          :icon="Plus"
          @click="createOpen = true"
        >
          发起投票
        </el-button>
      </div>
    </header>

    <el-alert
      v-if="errorMessage"
      :title="errorMessage"
      type="warning"
      :closable="false"
      show-icon
    />

    <div class="vote-grid">
      <aside class="panel vote-list" aria-label="可参与投票">
        <div class="panel-heading">
          <h2>可参与投票</h2>
          <span>{{ votes?.total ?? 0 }} 场</span>
        </div>
        <el-skeleton v-if="loading" :rows="6" animated />
        <el-empty v-else-if="!votes?.items.length" description="暂无可见投票" />
        <button
          v-for="vote in votes?.items"
          v-else
          :key="vote.id"
          type="button"
          :class="{ active: selectedVoteId === vote.id }"
          @click="selectVote(vote.id)"
        >
          <strong>{{ vote.title }}</strong>
          <small
            >{{
              vote.status === 'open' ? '进行中' : vote.status === 'published' ? '已结算' : '已截止'
            }}
            · {{ new Date(vote.closes_at).toLocaleString('zh-CN') }}</small
          >
        </button>
      </aside>

      <main class="panel ballot" aria-labelledby="ballot-title">
        <template v-if="selectedVote">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">当前议题</p>
              <h2 id="ballot-title">{{ selectedVote.title }}</h2>
            </div>
            <el-tag :type="selectedVote.status === 'open' ? 'success' : 'info'">{{
              selectedVote.status === 'open'
                ? '进行中'
                : selectedVote.status === 'published'
                  ? '已结算'
                  : '已截止'
            }}</el-tag>
          </div>
          <div class="options">
            <label
              v-for="option in selectedVote.options"
              :key="option.id"
              :class="{ selected: selectedOptionId === option.id }"
            >
              <input v-model="selectedOptionId" type="radio" name="ballot" :value="option.id" />
              <span>{{ option.label }}</span>
            </label>
          </div>
          <div class="credential-boundary">
            <el-icon><Lock /></el-icon>
            <div>
              <strong>{{
                credentialProviderReady ? '安全凭证组件已就绪' : '等待安全客户端凭证适配器'
              }}</strong>
              <p>
                {{
                  credentialProviderReady
                    ? '凭证只在内存中完成盲化与去盲，提交后立即释放。'
                    : '盲化、去盲和选票封装不得由页面 JavaScript 模拟；适配器接入后才能开放匿名提交。'
                }}
              </p>
            </div>
          </div>
          <el-button
            data-testid="submit-ballot"
            type="primary"
            :loading="ballotSubmitting"
            :disabled="
              !session.isAuthenticated ||
              !credentialProviderReady ||
              !selectedOptionId ||
              selectedVote.status !== 'open'
            "
            @click="submitAnonymousVote"
            >申领凭证并匿名投票</el-button
          >
          <el-alert
            v-if="ballotFeedback"
            class="ballot-feedback"
            :title="ballotFeedback"
            type="success"
            :closable="false"
            show-icon
          />
        </template>
        <el-empty v-else description="从左侧选择一场投票" />
      </main>

      <section class="panel result" aria-labelledby="result-title">
        <div class="panel-heading">
          <div>
            <p class="eyebrow">计票台签名</p>
            <h2 id="result-title">实时结果</h2>
          </div>
          <el-icon><Histogram /></el-icon>
        </div>
        <el-skeleton v-if="resultLoading" :rows="5" animated />
        <div v-else-if="result && selectedVote" class="bars">
          <div v-for="option in selectedVote.options" :key="option.id">
            <span>{{ option.label }}</span
            ><i
              ><b :style="{ width: `${((result.counts[option.id] ?? 0) / maxCount) * 100}%` }" /></i
            ><strong>{{ result.counts[option.id] ?? 0 }}</strong>
          </div>
          <p>
            有效票 {{ result.total }} · {{ new Date(result.published_at).toLocaleString('zh-CN') }}
          </p>
          <div class="result-actions">
            <el-button :icon="Check" :loading="actionLoading" @click="verifyResult"
              >验证结果签名</el-button
            >
            <el-button
              :icon="Download"
              :loading="actionLoading"
              :disabled="!auditReady"
              @click="downloadAudit"
              >导出匿名审计</el-button
            >
          </div>
          <p v-if="!auditReady" class="audit-note">
            匿名审计报告将在投票截止并完成最终结算后开放；当前可先验证实时结果签名。
          </p>
          <div
            v-if="verification"
            class="verify-state"
            :class="{ invalid: !verification.valid || !verification.certificate_valid }"
          >
            <el-icon
              ><component
                :is="verification.valid && verification.certificate_valid ? Check : WarningFilled"
            /></el-icon>
            <span>{{
              verification.valid && verification.certificate_valid
                ? '结果签名与证书均有效'
                : '结果签名验证未通过'
            }}</span>
          </div>
        </div>
        <el-empty v-else description="结果暂不可用" />
      </section>
    </div>

    <el-dialog v-model="createOpen" title="发起匿名投票" width="min(520px, 94vw)">
      <el-form label-position="top">
        <el-form-item label="议题"
          ><el-input v-model="createForm.title" maxlength="200"
        /></el-form-item>
        <el-form-item label="选项（每行一个）"
          ><el-input v-model="createForm.options" type="textarea" :rows="4"
        /></el-form-item>
        <div class="dialog-row">
          <el-form-item label="参与范围"
            ><el-select v-model="createForm.scope"
              ><el-option label="公开" value="public" /><el-option
                label="班级"
                value="class" /><el-option label="小组" value="group" /></el-select
          ></el-form-item>
          <el-form-item label="截止时间"
            ><el-date-picker
              v-model="createForm.closesAt"
              type="datetime"
              value-format="YYYY-MM-DDTHH:mm:ss"
          /></el-form-item>
        </div>
      </el-form>
      <template #footer
        ><el-button @click="createOpen = false">取消</el-button
        ><el-button type="primary" :loading="actionLoading" @click="submitCreate"
          >创建投票</el-button
        ></template
      >
    </el-dialog>
  </section>
</template>

<style scoped>
.vote-page {
  display: grid;
  gap: 16px;
}
.vote-heading,
.vote-heading > div,
.panel-heading,
.result-actions,
.dialog-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.vote-heading {
  align-items: flex-start;
}
.vote-heading > div:first-child {
  display: block;
}
.vote-heading h1 {
  margin: 4px 0 6px;
  color: var(--cc-primary-dark);
  font-size: 34px;
}
.vote-heading p:not(.eyebrow) {
  margin: 0;
  color: var(--cc-muted);
  font-size: 12px;
}
.eyebrow {
  margin: 0;
  color: var(--cc-primary);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.08em;
}
.vote-grid {
  display: grid;
  grid-template-columns: 240px minmax(320px, 1fr) minmax(300px, 0.9fr);
  gap: 14px;
}
.panel {
  min-width: 0;
  padding: 18px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.panel-heading {
  margin-bottom: 14px;
}
.panel-heading h2 {
  margin: 3px 0;
  color: var(--cc-primary-dark);
  font-size: 18px;
}
.panel-heading > span {
  color: var(--cc-muted);
  font-size: 10px;
}
.vote-list > button {
  display: grid;
  width: 100%;
  gap: 5px;
  margin-bottom: 8px;
  padding: 12px;
  border: 1px solid #dfe6ee;
  border-radius: 10px;
  text-align: left;
  background: #f9fbfd;
  cursor: pointer;
}
.vote-list > button.active {
  border-color: var(--cc-primary);
  background: #edf4fd;
}
.vote-list small {
  color: var(--cc-muted);
  font-size: 9px;
}
.options {
  display: grid;
  gap: 9px;
}
.options label {
  display: flex;
  gap: 10px;
  padding: 14px;
  border: 1px solid #dfe6ee;
  border-radius: 10px;
  cursor: pointer;
}
.options label.selected {
  border-color: var(--cc-primary);
  background: #edf4fd;
}
.credential-boundary {
  display: flex;
  gap: 10px;
  margin: 14px 0;
  padding: 12px;
  color: #665327;
  background: #fff9ea;
  border: 1px solid #d5a43a;
}
.credential-boundary p {
  margin: 3px 0 0;
  font-size: 9px;
  line-height: 1.5;
}
.bars {
  display: grid;
  gap: 12px;
}
.bars > div:not(.result-actions):not(.verify-state) {
  display: grid;
  grid-template-columns: 90px 1fr 28px;
  align-items: center;
  gap: 8px;
  font-size: 10px;
}
.bars i {
  height: 7px;
  overflow: hidden;
  border-radius: 8px;
  background: #edf1f5;
}
.bars b {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, var(--cc-primary), #4ba381);
}
.bars > p {
  margin: 4px 0;
  color: var(--cc-muted);
  font-size: 9px;
}
.result-actions {
  justify-content: flex-start;
  flex-wrap: wrap;
}
.audit-note {
  margin: 0;
  color: var(--cc-muted);
  font-size: 11px;
  line-height: 1.5;
}
.verify-state {
  display: flex !important;
  grid-template-columns: none !important;
  gap: 8px !important;
  padding: 10px;
  color: var(--cc-success);
  background: #edf8f1;
}
.verify-state.invalid {
  color: var(--cc-danger);
  background: #fff2f1;
}
.dialog-row > * {
  flex: 1;
}
@media (max-width: 1100px) {
  .vote-grid {
    grid-template-columns: 220px 1fr;
  }
  .result {
    grid-column: 1/-1;
  }
}
@media (max-width: 760px) {
  .vote-heading,
  .vote-grid,
  .dialog-row {
    display: grid;
    grid-template-columns: 1fr;
  }
  .vote-heading > div {
    justify-content: flex-start;
  }
  .result {
    grid-column: auto;
  }
}
</style>
