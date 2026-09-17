import type { components } from '@/api/schema'

export const studentUser = {
  id: '00000000-0000-4000-8000-000000000043',
  email: 'student@example.edu.cn',
  role: 'student',
  status: 'active',
  pqc_mode: false,
  created_at: '2026-09-03T00:00:00Z',
} satisfies components['schemas']['User']

export const authSession = {
  access_token: 'test-token-redacted',
  token_type: 'bearer',
  expires_in: 7200,
  user: studentUser,
} satisfies components['schemas']['AuthSession']

export const onlineSystemStatus = {
  api: 'ok',
  engine: 'online',
  version: 'test-version-redacted',
  tlcp: 'online',
  providers: {
    default: true,
    pqc: true,
  },
} satisfies components['schemas']['SystemStatus']
