import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import {
  acquireCredential,
  currentCredentialPeriod,
  hasCredentialProvider,
} from '@/security/credential-provider'

describe('安全匿名凭证提供器边界', () => {
  const commitment = {
    commitment_id: '0123456789abcdef0123456789abcdef',
    commitment_point: 'point-base64',
    signer_public_key: 'public-key-base64',
    expires_at: '2026-09-10T12:10:00Z',
    algorithm: 'SM2-BLIND-PROTOCOL-V1' as const,
  }
  afterEach(() => {
    delete window.cryptoCampusCredentialProvider
  })

  it('没有密码引擎客户端适配器时失败关闭且不调用签发接口', async () => {
    const issue = vi.fn()
    expect(hasCredentialProvider()).toBe(false)
    await expect(acquireCredential('hole_post', '2026-09-10', issue)).rejects.toEqual(
      expect.objectContaining<ApiError>({ code: 'CRYPTO_CLIENT_UNAVAILABLE' }),
    )
    expect(issue).not.toHaveBeenCalled()
  })

  it('只在内存中完成盲化、签发和去盲并校验绑定字段', async () => {
    const state = { opaque: true }
    const blind = vi.fn().mockResolvedValue({ blindedMessage: 'blinded-message', state })
    const unblind = vi.fn().mockResolvedValue({
      sn: 'secure-random-serial',
      service: 'vote_ballot',
      period: 'vote-42',
      signature: 'unblinded-signature',
    })
    window.cryptoCampusCredentialProvider = { blind, unblind }
    const issue = vi.fn().mockResolvedValue({
      blind_signature: 'blind-signature',
      algorithm: 'SM2-BLIND-PROTOCOL-V1',
    })

    await expect(
      acquireCredential('vote_ballot', 'vote-42', issue, async () => commitment, 'option-7'),
    ).resolves.toEqual(expect.objectContaining({ sn: 'secure-random-serial' }))
    expect(blind).toHaveBeenCalledWith({
      service: 'vote_ballot',
      period: 'vote-42',
      commitment,
      context: 'option-7',
    })
    expect(issue).toHaveBeenCalledWith('blinded-message')
    expect(unblind).toHaveBeenCalledWith(
      expect.objectContaining({ service: 'vote_ballot', period: 'vote-42', state }),
    )
  })

  it('拒绝适配器返回的跨服务凭证', async () => {
    window.cryptoCampusCredentialProvider = {
      blind: vi.fn().mockResolvedValue({ blindedMessage: 'blinded', state: null }),
      unblind: vi.fn().mockResolvedValue({
        sn: 'serial',
        service: 'hole_like',
        period: '2026-09-10',
        signature: 'signature',
      }),
    }

    await expect(
      acquireCredential(
        'hole_post',
        '2026-09-10',
        vi.fn().mockResolvedValue({
          blind_signature: 'blind-signature',
          algorithm: 'SM2-BLIND-PROTOCOL-V1',
        }),
        async () => commitment,
      ),
    ).rejects.toEqual(expect.objectContaining<ApiError>({ code: 'CRYPTO_CLIENT_INVALID' }))
  })

  it('支持 ADR-0001 两轮承诺流并向适配器传递承诺', async () => {
    const twoRoundCommitment = {
      commitment_id: '0123456789abcdef0123456789abcdef',
      commitment_point: '04' + '22'.repeat(64),
      expires_at: '2026-09-10T12:10:00Z',
      algorithm: 'SM2-BLIND-PROTOCOL-V1' as const,
      signer_public_key: 'public-key-base64',
    }
    const state = { sn: 'sn-dev-12345' }
    const blind = vi.fn().mockResolvedValue({ blindedMessage: 'blinded-48b', state })
    const unblind = vi.fn().mockResolvedValue({
      sn: 'sn-dev-12345',
      service: 'hole_post',
      period: '2026-09-10',
      signature: 'unblinded-sig',
    })
    window.cryptoCampusCredentialProvider = { blind, unblind }
    const issue = vi.fn().mockResolvedValue({
      blind_signature: 'server-blind-sig',
      algorithm: 'SM2-BLIND-PROTOCOL-V1',
    })
    const getCommitment = vi.fn().mockResolvedValue(twoRoundCommitment)

    const proof = await acquireCredential('hole_post', '2026-09-10', issue, getCommitment)
    expect(getCommitment).toHaveBeenCalled()
    expect(blind).toHaveBeenCalledWith({
      service: 'hole_post',
      period: '2026-09-10',
      commitment: twoRoundCommitment,
      context: undefined,
    })
    expect(issue).toHaveBeenCalledWith('blinded-48b')
    expect(proof.sn).toBe('sn-dev-12345')
  })

  it('以 UTC 日期生成每日凭证窗口', () => {
    expect(currentCredentialPeriod(new Date('2026-09-10T23:30:00-08:00'))).toBe('2026-09-11')
  })
})
