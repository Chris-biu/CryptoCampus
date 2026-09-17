import { defineConfig, devices } from '@playwright/test'

const python = process.env.E2E_PYTHON ?? 'python'

export default defineConfig({
  testDir: './runtime-specs',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report/runtime', open: 'never' }],
    ['junit', { outputFile: 'test-results/runtime-junit.xml' }],
  ],
  outputDir: 'test-results/runtime-artifacts',
  use: {
    baseURL: 'http://127.0.0.1:4174',
    screenshot: 'only-on-failure',
    trace: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'desktop-runtime-chromium',
      use: {
        ...devices['Desktop Chrome'],
        channel: process.env.CI ? undefined : 'chrome',
        viewport: { width: 1440, height: 1000 },
      },
    },
  ],
  webServer: [
    {
      command: `${python} -m uvicorn app.main:app --app-dir ../../server --host 127.0.0.1 --port 8002`,
      port: 8002,
      env: { CRYPTOCAMPUS_DATABASE_URL: 'sqlite+pysqlite:///:memory:' },
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: 'npm --prefix ../../web run dev -- --host 127.0.0.1 --port 4174 --force',
      port: 4174,
      env: { VITE_API_PROXY_TARGET: 'http://127.0.0.1:8002' },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
