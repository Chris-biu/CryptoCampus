import { afterEach, describe, expect, it } from 'vitest'

import {
  createDevCredentialProvider,
  installDevCredentialProvider,
  uninstallDevCredentialProvider,
} from '@/security/dev-credential-provider'

describe('Dev 凭证适配器 (ADR-0001 联调测试)', () => {
  afterEach(() => {
    uninstallDevCredentialProvider()
  })

  it('支持带有两轮承诺的盲化与去盲流程', async () => {
    const provider = createDevCredentialProvider()
    const commitment = {
      commitment_id: '0123456789abcdef0123456789abcdef',
      commitment_point: 'BMabc',
      expires_at: '2026-09-10T12:00:00Z',
      algorithm: 'SM2-BLIND-PROTOCOL-V1' as const,
    }

    const draft = await provider.blind({
      service: 'hole_post',
      period: '2026-09-10',
      commitment,
    })

    expect(draft.blindedMessage).toBeDefined()
    // 48 bytes base64 encoded is 64 chars
    expect(draft.blindedMessage.length).toBe(64)

    const proof = await provider.unblind({
      service: 'hole_post',
      period: '2026-09-10',
      response: {
        blind_signature: 'server-sig-base64',
        algorithm: 'SM2-BLIND-PROTOCOL-V1',
      },
      state: draft.state,
    })

    expect(proof.service).toBe('hole_post')
    expect(proof.period).toBe('2026-09-10')
    expect(proof.signature).toBe('server-sig-base64')
    expect(proof.sn).toBeDefined()
    expect(proof.sn.length).toBe(32)
  })

  it('支持无承诺的单轮盲化兜底流程', async () => {
    const provider = createDevCredentialProvider()
    const draft = await provider.blind({
      service: 'vote_ballot',
      period: 'vote-1',
    })

    expect(draft.blindedMessage).toBeDefined()
    // 32 bytes base64 is 44 chars
    expect(draft.blindedMessage.length).toBe(44)

    const proof = await provider.unblind({
      service: 'vote_ballot',
      period: 'vote-1',
      response: {
        blind_signature: 'vote-sig',
        algorithm: 'SM2-BLIND-PROTOCOL-V1',
      },
      state: null,
    })

    expect(proof.service).toBe('vote_ballot')
    expect(proof.period).toBe('vote-1')
    expect(proof.signature).toBe('vote-sig')
    expect(proof.sn.length).toBe(32)
  })

  it('支持在 window 对象上挂载与卸载', () => {
    expect(window.cryptoCampusCredentialProvider).toBeUndefined()
    installDevCredentialProvider()
    expect(window.cryptoCampusCredentialProvider).toBeDefined()
    uninstallDevCredentialProvider()
    expect(window.cryptoCampusCredentialProvider).toBeUndefined()
  })
})
