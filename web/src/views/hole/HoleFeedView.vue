<script setup lang="ts">
/* global crypto */
import { computed, onMounted, ref, shallowRef } from 'vue'
import {
  ChatDotRound,
  Check,
  InfoFilled,
  Lock,
  Plus,
  Refresh,
  Star,
  WarningFilled,
} from '@element-plus/icons-vue'

import {
  createHoleComment,
  createHoleCommitment,
  createHolePost,
  issueHoleCredential,
  likeHolePost,
  listHoleComments,
  listHolePosts,
  type HoleCommentPage,
  type HolePostPage,
} from '@/api/hole'
import { ApiError, messageForApiError } from '@/api/errors'
import {
  acquireCredential,
  currentCredentialPeriod,
  hasCredentialProvider,
  installDevCredentialProvider,
  uninstallDevCredentialProvider,
  type AnonymousService,
} from '@/security/credential-provider'
import { useSessionStore } from '@/stores/session'
import BlindSignatureFlow from './BlindSignatureFlow.vue'

const PAGE_SIZE = 10
const posts = shallowRef<HolePostPage | null>(null)
const currentPage = ref(1)
const isLoading = ref(false)
const errorMessage = ref('')
const requestSequence = ref(0)
const session = useSessionStore()
const composerOpen = ref(false)
const composerContent = ref('')
const composerError = ref('')
const actionLoading = ref(false)
const actionMessage = ref('')
const commentsPostId = ref('')
const comments = shallowRef<HoleCommentPage | null>(null)
const commentContent = ref('')
const commentsLoading = ref(false)
const isDev = Boolean(import.meta.env.DEV)
const devProviderVersion = ref(0)
const credentialProviderReady = computed(() => {
  void devProviderVersion.value
  return hasCredentialProvider()
})

function toggleDevProvider(): void {
  if (hasCredentialProvider()) {
    uninstallDevCredentialProvider()
  } else {
    installDevCredentialProvider()
  }
  devProviderVersion.value++
}

const publishedPosts = computed(
  () => posts.value?.items.filter((post) => post.status === 'published') ?? [],
)
const verifiedCount = computed(
  () => publishedPosts.value.filter((post) => post.credential_valid).length,
)

function safeDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '时间未知' : date.toLocaleString('zh-CN')
}

function safePrefix(value: string): string {
  const normalized = value.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 16)
  return normalized || '未提供'
}

function loadFailure(error: unknown): string {
  return error instanceof ApiError
    ? messageForApiError(error.code, error.status)
    : messageForApiError('UNKNOWN_ERROR')
}

async function load(page = currentPage.value): Promise<void> {
  const sequence = ++requestSequence.value
  isLoading.value = true
  errorMessage.value = ''
  try {
    const response = await listHolePosts(page, PAGE_SIZE)
    if (sequence !== requestSequence.value) return
    posts.value = response
    currentPage.value = response.page
  } catch (error) {
    if (sequence !== requestSequence.value) return
    posts.value = null
    errorMessage.value = loadFailure(error)
  } finally {
    if (sequence === requestSequence.value) isLoading.value = false
  }
}

function changePage(page: number): void {
  void load(page)
}

async function credentialFor(service: AnonymousService) {
  if (!session.accessToken) throw new ApiError({ code: 'HTTP_401', status: 401 })
  const period = currentCredentialPeriod()
  return acquireCredential(
    service,
    period,
    (blindedMessage) =>
      issueHoleCredential(
        { service, period, blinded_message: blindedMessage },
        session.accessToken!,
        crypto.randomUUID(),
      ),
    () => createHoleCommitment({ service, period }, session.accessToken!),
  )
}

async function publishPost(): Promise<void> {
  const content = composerContent.value.trim()
  if (!content || content.length > 2000 || actionLoading.value) return
  actionLoading.value = true
  actionMessage.value = ''
  errorMessage.value = ''
  composerError.value = ''
  try {
    const credential = await credentialFor('hole_post')
    await createHolePost({ content, credential }, session.accessToken!, crypto.randomUUID())
    composerContent.value = ''
    composerOpen.value = false
    actionMessage.value = '帖子已匿名发布，页面未保存凭证或盲化因子。'
    await load(1)
  } catch (error) {
    composerError.value = loadFailure(error)
  } finally {
    actionLoading.value = false
  }
}

function openComposer(): void {
  composerError.value = ''
  composerOpen.value = true
}

async function openComments(postId: string): Promise<void> {
  commentsPostId.value = postId
  comments.value = null
  commentContent.value = ''
  commentsLoading.value = true
  errorMessage.value = ''
  try {
    comments.value = await listHoleComments(postId)
  } catch (error) {
    errorMessage.value = loadFailure(error)
  } finally {
    commentsLoading.value = false
  }
}

async function publishComment(): Promise<void> {
  const content = commentContent.value.trim()
  if (!commentsPostId.value || !content || content.length > 1000 || actionLoading.value) return
  actionLoading.value = true
  errorMessage.value = ''
  try {
    const credential = await credentialFor('hole_comment')
    await createHoleComment(commentsPostId.value, { content, credential }, crypto.randomUUID())
    commentContent.value = ''
    comments.value = await listHoleComments(commentsPostId.value)
  } catch (error) {
    errorMessage.value = loadFailure(error)
  } finally {
    actionLoading.value = false
  }
}

async function like(postId: string): Promise<void> {
  if (actionLoading.value) return
  actionLoading.value = true
  errorMessage.value = ''
  try {
    const credential = await credentialFor('hole_like')
    await likeHolePost(postId, credential, crypto.randomUUID())
    actionMessage.value = '匿名点赞已记录。'
  } catch (error) {
    errorMessage.value = loadFailure(error)
  } finally {
    actionLoading.value = false
  }
}

onMounted(() => void load())
</script>

<template>
  <section class="hole-page" aria-labelledby="hole-title">
    <header class="hole-heading">
      <div>
        <p class="eyebrow">公开浏览 · FR-05</p>
        <h1 id="hole-title">匿名树洞</h1>
        <p>只展示公开内容和凭证前缀；页面与接口都不提供发布者身份。</p>
      </div>
      <div class="heading-actions">
        <el-button :icon="Refresh" :loading="isLoading" @click="load(currentPage)"
          >刷新热榜</el-button
        >
        <el-button
          v-if="session.isAuthenticated"
          type="primary"
          :icon="Plus"
          :disabled="!credentialProviderReady"
          @click="openComposer"
          >匿名发布</el-button
        >
      </div>
    </header>

    <section class="privacy-ribbon" aria-label="匿名性边界">
      <div class="ribbon-mark">
        <el-icon><Lock /></el-icon>
      </div>
      <div>
        <strong>匿名不是“没有规则”</strong>
        <p>一次性凭证用于证明发布资格；前缀用于公开核验，不等于账号或真实身份。</p>
      </div>
      <span>浏览无需登录</span>
    </section>

    <div
      v-if="isDev"
      class="dev-provider-banner"
      style="
        margin-bottom: 1rem;
        padding: 0.75rem 1.25rem;
        background: #f0fdf4;
        border: 1px dashed #16a34a;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
      "
    >
      <div style="font-size: 0.875rem; color: #15803d; line-height: 1.5">
        <strong>【开发调试适配器】</strong>
        <span>{{
          credentialProviderReady
            ? '安全凭证适配器已挂载（支持真实联调 ADR-0001 SM2 盲签名两轮承诺协议）'
            : '未挂载凭证适配器（处于 Fail-Closed 默认安全关闭状态）'
        }}</span>
      </div>
      <el-button
        size="small"
        :type="credentialProviderReady ? 'default' : 'success'"
        @click="toggleDevProvider"
      >
        {{
          credentialProviderReady
            ? '卸载适配器 (恢复 Fail-Closed)'
            : '挂载 Dev 适配器 (联调两轮协议)'
        }}
      </el-button>
    </div>

    <el-alert
      v-if="!credentialProviderReady"
      title="浏览功能可用；匿名发布、评论和点赞等待密码引擎提供安全客户端凭证适配器。"
      type="info"
      :closable="false"
      show-icon
    />
    <el-alert
      v-if="actionMessage"
      :title="actionMessage"
      type="success"
      :closable="false"
      show-icon
    />

    <div class="feed-layout">
      <aside class="context-panel" aria-label="树洞说明">
        <p class="eyebrow">今日窗口</p>
        <strong class="big-number">{{ posts?.total ?? '—' }}</strong>
        <span>接口返回的公开记录</span>
        <dl>
          <div>
            <dt>本页公开</dt>
            <dd>{{ publishedPosts.length }}</dd>
          </div>
          <div>
            <dt>凭证有效</dt>
            <dd>{{ verifiedCount }}</dd>
          </div>
          <div>
            <dt>每页</dt>
            <dd>{{ PAGE_SIZE }}</dd>
          </div>
        </dl>
        <div class="boundary-note">
          <el-icon><InfoFilled /></el-icon>
          <p>热榜顺序完全采用后端返回顺序。当前契约没有热度分值，前端不自行编造排名。</p>
        </div>
      </aside>

      <section class="feed-panel" aria-labelledby="feed-title" aria-busy="isLoading">
        <div class="feed-title">
          <div>
            <p class="eyebrow">凭证可核验的公开内容</p>
            <h2 id="feed-title">今日热榜</h2>
          </div>
          <span>第 {{ currentPage }} 页</span>
        </div>

        <el-skeleton v-if="isLoading" :rows="6" animated />
        <div v-else-if="errorMessage" class="state-panel" role="alert">
          <el-icon><WarningFilled /></el-icon>
          <div>
            <strong>热榜加载失败</strong>
            <p>{{ errorMessage }}</p>
          </div>
          <el-button :icon="Refresh" @click="load(currentPage)">重新加载</el-button>
        </div>
        <el-empty v-else-if="publishedPosts.length === 0" description="暂时没有可公开展示的帖子" />

        <div v-else class="post-list">
          <article
            v-for="(post, index) in publishedPosts"
            :key="post.id"
            :class="{ unverified: !post.credential_valid }"
          >
            <div class="post-index" aria-hidden="true">
              {{ String(index + 1).padStart(2, '0') }}
            </div>
            <div class="post-body">
              <div class="post-meta">
                <span class="post-id">记录 {{ post.id.slice(0, 8) }}</span>
                <time :datetime="post.created_at">{{ safeDate(post.created_at) }}</time>
              </div>
              <p v-if="post.credential_valid">{{ post.content }}</p>
              <p v-else class="blocked-copy">凭证验证未通过，内容已停止展示。</p>
              <div v-if="post.credential_valid" class="post-actions">
                <el-button text :icon="ChatDotRound" @click="openComments(post.id)">评论</el-button>
                <el-button
                  v-if="session.isAuthenticated"
                  text
                  :icon="Star"
                  :disabled="!credentialProviderReady"
                  :loading="actionLoading"
                  @click="like(post.id)"
                  >匿名点赞</el-button
                >
              </div>
            </div>
            <div class="credential-stamp" :class="{ invalid: !post.credential_valid }">
              <el-icon><component :is="post.credential_valid ? Check : WarningFilled" /></el-icon>
              <span>
                <strong>{{ post.credential_valid ? '凭证验签通过' : '凭证验签未通过' }}</strong>
                <small>{{ safePrefix(post.credential_prefix) }}…</small>
              </span>
            </div>
          </article>
        </div>

        <el-pagination
          v-if="posts && posts.total > PAGE_SIZE"
          class="feed-pagination"
          background
          layout="prev, pager, next"
          :current-page="currentPage"
          :page-size="PAGE_SIZE"
          :total="posts.total"
          :disabled="isLoading"
          @current-change="changePage"
        />
      </section>
    </div>
    <el-dialog v-model="composerOpen" title="发布匿名树洞" width="min(620px, 94vw)">
      <el-input
        v-model="composerContent"
        type="textarea"
        :rows="7"
        maxlength="2000"
        show-word-limit
        placeholder="写下要公开发布的内容"
      />
      <p class="dialog-note">发布时由安全组件在内存中生成一次性凭证，页面不会保存身份关联。</p>
      <el-alert
        v-if="composerError"
        class="dialog-error"
        :title="composerError"
        type="error"
        :closable="false"
        show-icon
      />
      <template #footer>
        <el-button @click="composerOpen = false">取消</el-button>
        <el-button
          type="primary"
          :loading="actionLoading"
          :disabled="!composerContent.trim()"
          @click="publishPost"
          >申领凭证并发布</el-button
        >
      </template>
    </el-dialog>

    <el-drawer
      :model-value="Boolean(commentsPostId)"
      title="匿名评论"
      size="520px"
      @close="commentsPostId = ''"
    >
      <el-skeleton v-if="commentsLoading" :rows="5" animated />
      <el-empty v-else-if="!comments?.items.length" description="暂时没有评论" />
      <div v-else class="comment-list">
        <article v-for="comment in comments.items" :key="comment.id">
          <p>{{ comment.credential_valid ? comment.content : '凭证验证未通过，评论已隐藏。' }}</p>
          <small
            >{{ safeDate(comment.created_at) }} ·
            {{ safePrefix(comment.credential_prefix) }}…</small
          >
        </article>
      </div>
      <div v-if="session.isAuthenticated" class="comment-composer">
        <el-input
          v-model="commentContent"
          type="textarea"
          :rows="3"
          maxlength="1000"
          show-word-limit
          placeholder="匿名评论"
        />
        <el-button
          type="primary"
          :loading="actionLoading"
          :disabled="!credentialProviderReady || !commentContent.trim()"
          @click="publishComment"
          >申领凭证并评论</el-button
        >
      </div>
    </el-drawer>
    <BlindSignatureFlow />
  </section>
</template>

<style scoped>
.hole-page {
  display: grid;
  gap: 16px;
}

.dialog-error {
  margin-top: 14px;
}

.hole-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
}

.heading-actions,
.post-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.eyebrow {
  margin: 0;
  color: var(--cc-primary);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.hole-heading h1 {
  margin: 4px 0 6px;
  color: var(--cc-primary-dark);
  font-size: 34px;
}

.hole-heading p:not(.eyebrow) {
  margin: 0;
  color: var(--cc-muted);
  font-size: 12px;
}

.privacy-ribbon {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr) auto;
  align-items: center;
  gap: 13px;
  padding: 13px 16px;
  border: 1px solid #c8d9ee;
  border-radius: 12px;
  color: var(--cc-primary-dark);
  background: linear-gradient(90deg, #edf4fd, #fff);
}

.ribbon-mark {
  display: grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border-radius: 50%;
  color: #fff;
  background: var(--cc-primary-dark);
}

.privacy-ribbon strong,
.privacy-ribbon p {
  display: block;
  margin: 0;
}

.privacy-ribbon p {
  margin-top: 3px;
  color: var(--cc-muted);
  font-size: 10px;
}

.privacy-ribbon > span {
  padding: 5px 9px;
  border-radius: 999px;
  color: var(--cc-success);
  background: #e8f6ee;
  font-size: 10px;
  font-weight: 750;
}

.feed-layout {
  display: grid;
  grid-template-columns: 245px minmax(0, 1fr);
  gap: 16px;
}

.context-panel,
.feed-panel {
  min-width: 0;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}

.context-panel {
  align-self: start;
  padding: 22px;
}

.big-number {
  display: block;
  margin-top: 12px;
  color: var(--cc-primary-dark);
  font:
    800 46px/1 'Cascadia Code',
    Consolas,
    monospace;
}

.context-panel > span {
  color: var(--cc-muted);
  font-size: 10px;
}

.context-panel dl {
  display: grid;
  margin: 20px 0;
  border-top: 1px solid #e7ebf0;
}

.context-panel dl div {
  display: flex;
  justify-content: space-between;
  padding: 9px 0;
  border-bottom: 1px solid #e7ebf0;
  font-size: 10px;
}

.context-panel dt {
  color: var(--cc-muted);
}

.context-panel dd {
  margin: 0;
  color: var(--cc-primary-dark);
  font-weight: 800;
}

.boundary-note {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 11px;
  border-left: 3px solid #d5a43a;
  color: #665327;
  background: #fff9ea;
}

.boundary-note .el-icon {
  flex: 0 0 auto;
  margin-top: 2px;
}

.boundary-note p {
  margin: 0;
  font-size: 9px;
  line-height: 1.55;
}

.feed-panel {
  min-height: 520px;
  padding: 20px;
}

.feed-title {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  margin-bottom: 14px;
  padding-bottom: 12px;
  border-bottom: 1px solid #e7ebf0;
}

.feed-title h2 {
  margin: 4px 0 0;
  color: var(--cc-primary-dark);
  font-size: 20px;
}

.feed-title > span {
  color: var(--cc-muted);
  font:
    700 10px/1 'Cascadia Code',
    Consolas,
    monospace;
}

.post-list {
  display: grid;
  gap: 9px;
}

.post-list article {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr) 178px;
  align-items: stretch;
  overflow: hidden;
  border: 1px solid #dde4ec;
  border-radius: 10px;
  background: #fbfcfe;
}

.post-index {
  display: grid;
  place-items: center;
  color: #7c9ec7;
  background: #edf3fb;
  font:
    800 10px/1 'Cascadia Code',
    Consolas,
    monospace;
}

.post-body {
  min-width: 0;
  padding: 12px 14px;
}

.post-meta {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  color: var(--cc-muted);
  font-size: 9px;
}

.post-id {
  font-family: 'Cascadia Code', Consolas, monospace;
}

.post-body > p {
  margin: 8px 0 0;
  overflow-wrap: anywhere;
  color: #303d4f;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
}

.post-body > p.blocked-copy {
  color: var(--cc-danger);
  font-weight: 700;
}

.post-actions {
  margin-top: 8px;
}

.dialog-note {
  margin: 12px 0 0;
  color: var(--cc-muted);
  font-size: 11px;
  line-height: 1.6;
}

.comment-list {
  display: grid;
  gap: 10px;
}

.comment-list article {
  padding: 13px;
  border: 1px solid var(--cc-line);
  border-radius: 9px;
  background: #f8fafc;
}

.comment-list p {
  margin: 0 0 7px;
  color: var(--cc-ink);
  line-height: 1.6;
  white-space: pre-wrap;
}

.comment-list small {
  color: var(--cc-muted);
}

.comment-composer {
  display: grid;
  gap: 10px;
  margin-top: 18px;
  padding-top: 18px;
  border-top: 1px solid var(--cc-line);
}

.comment-composer .el-button {
  justify-self: end;
}

.credential-stamp {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 11px;
  border-left: 1px dashed #9dc8ad;
  color: var(--cc-success);
  background: #f0f9f4;
}

.credential-stamp.invalid {
  border-left-color: #dfaaa5;
  color: var(--cc-danger);
  background: #fff3f2;
}

.credential-stamp strong,
.credential-stamp small {
  display: block;
}

.credential-stamp strong {
  font-size: 10px;
}

.credential-stamp small {
  margin-top: 4px;
  color: var(--cc-muted);
  font:
    700 9px/1 'Cascadia Code',
    Consolas,
    monospace;
}

.state-panel {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 18px;
  border-radius: 10px;
  color: #74453f;
  background: #fff4f2;
}

.state-panel > .el-icon {
  font-size: 24px;
}

.state-panel > div {
  flex: 1;
}

.state-panel p {
  margin: 3px 0 0;
  color: var(--cc-muted);
  font-size: 10px;
}

.feed-pagination {
  justify-content: center;
  margin-top: 16px;
}

@media (max-width: 1000px) {
  .feed-layout {
    grid-template-columns: 1fr;
  }
  .context-panel {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 10px 20px;
  }
  .context-panel dl,
  .boundary-note {
    grid-column: 1 / -1;
  }
}

@media (max-width: 720px) {
  .privacy-ribbon {
    grid-template-columns: 42px minmax(0, 1fr);
  }
  .privacy-ribbon > span {
    display: none;
  }
  .post-list article {
    grid-template-columns: 32px minmax(0, 1fr);
  }
  .credential-stamp {
    grid-column: 2;
    border-top: 1px dashed #9dc8ad;
    border-left: 0;
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
