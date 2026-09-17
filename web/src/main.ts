import { createApp } from 'vue'

import App from '@/App.vue'
import { pinia } from '@/stores'
import { router } from '@/router'
import '@/styles/main.css'
import { installWasmCredentialProvider } from '@/security/wasm-credential-provider'

async function bootstrap(): Promise<void> {
  try {
    await installWasmCredentialProvider()
  } catch {
    delete window.cryptoCampusCredentialProvider
  }
  createApp(App).use(pinia).use(router).mount('#app')
}

void bootstrap()
