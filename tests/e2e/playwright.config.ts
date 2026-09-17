import { defineConfig, devices } from '@playwright/test'

const python = process.env.E2E_PYTHON ?? 'python'

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['junit', { outputFile: 'test-results/junit.xml' }],
  ],
  outputDir: 'test-results/artifacts',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'off',
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: {
        ...devices['Desktop Chrome'],
        channel: process.env.CI ? undefined : 'chrome',
        viewport: { width: 1440, height: 1000 },
      },
    },
  ],
  webServer: [
    {
      command: `${python} -m uvicorn support.app:app --host 127.0.0.1 --port 8001`,
      port: 8001,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: 'npm --prefix ../../web run dev -- --host 127.0.0.1 --port 4173 --force',
      port: 4173,
      env: { VITE_API_PROXY_TARGET: 'http://127.0.0.1:8001' },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
