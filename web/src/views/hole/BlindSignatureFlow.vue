<script setup lang="ts">
/* global window */
import { computed, onBeforeUnmount, ref } from 'vue'
import { CaretRight, RefreshRight, VideoPause } from '@element-plus/icons-vue'

const steps = [
  {
    title: '生成随机序列号',
    detail: '安全客户端向密码引擎申请至少 128 bit 的随机 SN。',
    actor: '客户端',
  },
  {
    title: '绑定业务上下文',
    detail: '组装 M = SN ‖ service ‖ period，两轮协议申领服务端随机承诺 R，阻止凭证跨服务跨周期挪用。',
    actor: '客户端 + 服务端',
  },
  {
    title: '盲化待签消息',
    detail: '密码引擎结合承诺 R 与盲化因子 α, β 处理 M 得到 c\'；页面不接触因子或密码中间值。',
    actor: '密码引擎',
  },
  {
    title: '额度校验与盲签',
    detail: '服务器只看到盲化值，原子核验并销毁承诺防重放，完成盲签得到 s\'。',
    actor: '服务器',
  },
  {
    title: '去盲并一次性消费',
    detail: '客户端去盲得到凭证 (SN, σ)；发布时验签并登记 SN，重复提交返回冲突。',
    actor: '客户端 + 服务器',
  },
] as const

const activeStep = ref(0)
const isPlaying = ref(false)
let timer: number | undefined

const progress = computed(() => ((activeStep.value + 1) / steps.length) * 100)

function stop(): void {
  isPlaying.value = false
  if (timer) window.clearInterval(timer)
  timer = undefined
}

function next(): void {
  if (activeStep.value >= steps.length - 1) {
    stop()
    return
  }
  activeStep.value += 1
  if (activeStep.value === steps.length - 1) stop()
}

function togglePlayback(): void {
  if (isPlaying.value) {
    stop()
    return
  }
  if (activeStep.value === steps.length - 1) activeStep.value = 0
  isPlaying.value = true
  timer = window.setInterval(next, 1400)
}

function reset(): void {
  stop()
  activeStep.value = 0
}

onBeforeUnmount(stop)
</script>

<template>
  <section class="blind-flow" aria-labelledby="blind-flow-title">
    <header>
      <div>
        <p class="eyebrow">盲签名教学 · Issue #21</p>
        <h2 id="blind-flow-title">一次性匿名凭证的五步流程</h2>
        <p>这里只回放协议职责，不在浏览器中生成凭证、盲化因子或签名。</p>
      </div>
      <div class="flow-actions">
        <el-button :icon="RefreshRight" @click="reset">重置</el-button>
        <el-button type="primary" :icon="isPlaying ? VideoPause : CaretRight" @click="togglePlayback">
          {{ isPlaying ? '暂停' : '播放流程' }}
        </el-button>
      </div>
    </header>

    <el-progress :percentage="progress" :show-text="false" :stroke-width="5" />

    <ol aria-label="盲签名协议步骤">
      <li
        v-for="(step, index) in steps"
        :key="step.title"
        :class="{ active: index === activeStep, done: index < activeStep }"
        :aria-current="index === activeStep ? 'step' : undefined"
      >
        <button type="button" @click="activeStep = index">
          <span>{{ String(index + 1).padStart(2, '0') }}</span>
          <strong>{{ step.title }}</strong>
          <small>{{ step.actor }}</small>
        </button>
      </li>
    </ol>

    <div class="step-detail" role="status" aria-live="polite">
      <span>{{ String(activeStep + 1).padStart(2, '0') }}</span>
      <div>
        <strong>{{ steps[activeStep].title }}</strong>
        <p>{{ steps[activeStep].detail }}</p>
      </div>
      <el-button :disabled="activeStep === steps.length - 1" @click="next">下一步</el-button>
    </div>

    <p class="boundary-copy">
      匿名性边界：签名对象固定绑定 <code>M = SN ‖ service ‖ period</code>。服务器知道账号在某周期申领过凭证，但不能把具体凭证与帖子关联；申领后立即发布仍可能暴露时间关联。
    </p>
  </section>
</template>

<style scoped>
.blind-flow {
  display: grid;
  gap: 16px;
  padding: 20px;
  border: 1px solid var(--cc-line);
  border-radius: 14px;
  background: #fff;
  box-shadow: var(--cc-shadow);
}
.blind-flow header,
.flow-actions,
.step-detail {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.blind-flow h2 {
  margin: 4px 0;
  color: var(--cc-primary-dark);
  font-size: 20px;
}
.blind-flow header p:not(.eyebrow),
.step-detail p,
.boundary-copy {
  margin: 0;
  color: var(--cc-muted);
  font-size: 10px;
  line-height: 1.55;
}
.blind-flow ol {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.blind-flow li button {
  display: grid;
  width: 100%;
  min-height: 92px;
  padding: 12px;
  border: 1px solid #dfe6ee;
  border-radius: 10px;
  color: #68778b;
  text-align: left;
  background: #f7f9fc;
  cursor: pointer;
}
.blind-flow li span {
  color: #90a0b4;
  font: 800 10px/1 'Cascadia Code', Consolas, monospace;
}
.blind-flow li strong {
  align-self: end;
  margin-top: 12px;
  font-size: 11px;
}
.blind-flow li small {
  margin-top: 4px;
  font-size: 9px;
}
.blind-flow li.active button {
  border-color: var(--cc-primary);
  color: var(--cc-primary-dark);
  background: #edf4fd;
  box-shadow: inset 0 0 0 1px var(--cc-primary);
}
.blind-flow li.done button {
  color: #28704a;
  background: #eef8f2;
}
.step-detail {
  min-height: 72px;
  padding: 14px;
  border-left: 4px solid var(--cc-primary);
  background: #f5f8fc;
}
.step-detail > span {
  color: var(--cc-primary);
  font: 800 22px/1 'Cascadia Code', Consolas, monospace;
}
.step-detail > div {
  flex: 1;
}
.step-detail strong {
  color: var(--cc-primary-dark);
  font-size: 12px;
}
.boundary-copy {
  padding: 10px 12px;
  border-radius: 8px;
  color: #665327;
  background: #fff9ea;
}
@media (max-width: 900px) {
  .blind-flow ol {
    grid-template-columns: 1fr;
  }
  .blind-flow li button {
    min-height: 0;
  }
}
@media (max-width: 640px) {
  .blind-flow header,
  .step-detail {
    align-items: stretch;
    flex-direction: column;
  }
  .flow-actions {
    justify-content: flex-start;
  }
}
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
</style>
