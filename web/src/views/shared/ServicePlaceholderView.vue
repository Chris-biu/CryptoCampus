<script setup lang="ts">
defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <section class="placeholder-page" aria-labelledby="placeholder-title">
    <p class="eyebrow">CryptoCampus</p>
    <h1 id="placeholder-title">{{ title }}</h1>
    <p>{{ description }}</p>
    <el-alert
      title="功能尚未接入"
      description="这里不会显示伪造的成功数据；接口可用后将严格按 OpenAPI 契约实现。"
      type="info"
      :closable="false"
      show-icon
    />
  </section>
</template>
