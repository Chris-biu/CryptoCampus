<script setup lang="ts">
defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <main id="main-content" class="standalone-page">
    <section class="placeholder-page" :aria-labelledby="`standalone-${String($route.name)}`">
      <p class="eyebrow">CryptoCampus</p>
      <h1 :id="`standalone-${String($route.name)}`">{{ title }}</h1>
      <p>{{ description }}</p>
      <el-alert
        title="功能尚未接入"
        description="这里不会显示伪造的成功数据；接口可用后将严格按 OpenAPI 契约实现。"
        type="info"
        :closable="false"
        show-icon
      />
    </section>
  </main>
</template>
