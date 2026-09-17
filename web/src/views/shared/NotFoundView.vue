<template>
  <main id="main-content" class="not-found-page">
    <p class="eyebrow">404</p>
    <h1>页面不存在</h1>
    <p>你访问的地址可能已失效，或尚未开放。</p>
    <RouterLink class="text-link" :to="{ name: 'home' }">返回服务大厅</RouterLink>
  </main>
</template>
