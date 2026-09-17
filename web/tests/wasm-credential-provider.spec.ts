import { afterEach, describe, expect, it, vi } from 'vitest'

import createCcWasmModule from '@/security/cc-client.generated.js'
import {
  createWasmCredentialProvider,
  installWasmCredentialProvider,
} from '@/security/wasm-credential-provider'

vi.mock('@/security/cc-client.generated.js', () => ({ default: vi.fn() }))

interface TestModule {
  HEAPU8: Uint8Array
  _malloc: ReturnType<typeof vi.fn>
  _free: ReturnType<typeof vi.fn>
  _cc_client_scalar_is_valid: ReturnType<typeof vi.fn>
  _cc_client_blind: ReturnType<typeof vi.fn>
  _cc_client_unblind: ReturnType<typeof vi.fn>
  _cc_client_credential: ReturnType<typeof vi.fn>
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function makeModule(overrides: Partial<TestModule> = {}): TestModule {
  const memory = new Uint8Array(8192)
  let nextPointer = 64
  const module: TestModule = {
    HEAPU8: memory,
    _malloc: vi.fn((size: number) => {
      const pointer = nextPointer
      nextPointer += size + 16
      return pointer
    }),
    _free: vi.fn(),
    _cc_client_scalar_is_valid: vi.fn(() => 1),
    _cc_client_blind: vi.fn(
      (_pk, _commitment, _message, _messageLength, _alpha, _beta, cPrime, state, rPrime) => {
        memory.fill(0x33, cPrime, cPrime + 32)
        memory.fill(0x44, state, state + 64)
        memory.fill(0x55, rPrime, rPrime + 65)
        memory[rPrime] = 0x04
        return 0
      },
    ),
    _cc_client_unblind: vi.fn((_sPrime, _state, output) => {
      memory.fill(0x66, output, output + 32)
      return 0
    }),
    _cc_client_credential: vi.fn((_rPrime, _s, output) => {
      memory.fill(0x77, output, output + 64)
      return 0
    }),
    ...overrides,
  }
  return module
}

function commitment() {
  return {
    commitment_id: '0123456789abcdef0123456789abcdef',
    commitment_point: base64(Uint8Array.from([0x04, ...new Uint8Array(64).fill(0x22)])),
    signer_public_key: base64(Uint8Array.from([0x04, ...new Uint8Array(64).fill(0x11)])),
    expires_at: '2026-09-17T03:00:00Z',
    algorithm: 'SM2-BLIND-PROTOCOL-V1' as const,
  }
}

afterEach(() => {
  vi.restoreAllMocks()
  delete window.cryptoCampusCredentialProvider
})

describe('真实 WASM 匿名凭证适配器', () => {
  it('在浏览器内完成盲化、去盲和凭证打包，并清零临时内存', async () => {
    const module = makeModule()
    let randomByte = 0x10
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((target) => {
      new Uint8Array(target.buffer, target.byteOffset, target.byteLength).fill((randomByte += 1))
      return target
    })
    const provider = createWasmCredentialProvider(module)

    const blinded = await provider.blind({
      service: 'hole_post',
      period: '2026-09-17',
      commitment: commitment(),
    })
    const payload = Uint8Array.from(atob(blinded.blindedMessage), (value) => value.charCodeAt(0))
    expect(payload).toHaveLength(48)
    const commitmentId = Uint8Array.from(
      '0123456789abcdef0123456789abcdef'.match(/../g)!.map((pair) => Number.parseInt(pair, 16)),
    )
    expect(Array.from(payload.slice(0, 16))).toEqual(Array.from(commitmentId))
    expect(Array.from(payload.slice(16))).toEqual(Array.from(new Uint8Array(32).fill(0x33)))

    const proof = await provider.unblind({
      service: 'hole_post',
      period: '2026-09-17',
      response: {
        blind_signature: base64(new Uint8Array(32).fill(0x55)),
        algorithm: 'SM2-BLIND-PROTOCOL-V1',
      },
      state: blinded.state,
    })
    expect(proof).toEqual({
      sn: '11'.repeat(16),
      service: 'hole_post',
      period: '2026-09-17',
      signature: base64(new Uint8Array(64).fill(0x77)),
    })
    expect(module._cc_client_blind).toHaveBeenCalledOnce()
    expect(module._cc_client_unblind).toHaveBeenCalledOnce()
    expect(module._cc_client_credential).toHaveBeenCalledOnce()
    expect(module._free).toHaveBeenCalled()
  })

  it('拒绝缺失承诺、非法点和非法去盲状态', async () => {
    const provider = createWasmCredentialProvider(makeModule())
    await expect(provider.blind({ service: 'hole_post', period: '2026-09-17' })).rejects.toThrow(
      'blind commitment unavailable',
    )
    await expect(
      provider.blind({
        service: 'hole_post',
        period: '2026-09-17',
        commitment: { ...commitment(), commitment_point: base64(new Uint8Array(65)) },
      }),
    ).rejects.toThrow('invalid SM2 point')
    await expect(
      provider.unblind({
        service: 'hole_post',
        period: '2026-09-17',
        response: {
          blind_signature: base64(new Uint8Array(31)),
          algorithm: 'SM2-BLIND-PROTOCOL-V1',
        },
        state: undefined,
      }),
    ).rejects.toThrow('invalid blind-signature state')
  })

  it('匿名选票盲签消息绑定投票和选项 UUID', async () => {
    const module = makeModule()
    let capturedMessage = new Uint8Array()
    module._cc_client_blind.mockImplementation(
      (_pk, _commitment, message, messageLength, _alpha, _beta, cPrime, state, rPrime) => {
        capturedMessage = module.HEAPU8.slice(message, message + messageLength)
        module.HEAPU8.fill(0x33, cPrime, cPrime + 32)
        module.HEAPU8.fill(0x44, state, state + 64)
        module.HEAPU8.fill(0x55, rPrime, rPrime + 65)
        module.HEAPU8[rPrime] = 0x04
        return 0
      },
    )
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((target) => {
      new Uint8Array(target.buffer, target.byteOffset, target.byteLength).fill(0x21)
      return target
    })
    const voteId = '30000000-0000-4000-8000-000000000001'
    const optionId = '40000000-0000-4000-8000-000000000001'

    await createWasmCredentialProvider(module).blind({
      service: 'vote_ballot',
      period: voteId,
      context: optionId,
      commitment: commitment(),
    })

    expect(new TextDecoder().decode(capturedMessage.slice(0, 28))).toBe(
      'CryptoCampus-Vote-Ballot-v1\0',
    )
    expect(Array.from(capturedMessage.slice(-32, -16))).toEqual(
      Array.from(uuidBytesForTest(voteId)),
    )
    expect(Array.from(capturedMessage.slice(-16))).toEqual(Array.from(uuidBytesForTest(optionId)))
  })

  it('对 WASM 盲化或去盲错误失败关闭', async () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((target) => {
      new Uint8Array(target.buffer, target.byteOffset, target.byteLength).fill(1)
      return target
    })
    const blindFailure = createWasmCredentialProvider(
      makeModule({ _cc_client_blind: vi.fn(() => 7) }),
    )
    await expect(
      blindFailure.blind({ service: 'hole_like', period: '2026-09-17', commitment: commitment() }),
    ).rejects.toThrow('cc_client_blind failed: 7')

    const module = makeModule({ _cc_client_unblind: vi.fn(() => 5) })
    const provider = createWasmCredentialProvider(module)
    const blinded = await provider.blind({
      service: 'hole_like',
      period: '2026-09-17',
      commitment: commitment(),
    })
    await expect(
      provider.unblind({
        service: 'hole_like',
        period: '2026-09-17',
        response: {
          blind_signature: base64(new Uint8Array(32)),
          algorithm: 'SM2-BLIND-PROTOCOL-V1',
        },
        state: blinded.state,
      }),
    ).rejects.toThrow('cc_client_unblind failed')
  })

  it('加载固定 WASM 路径并注入全局提供器', async () => {
    const module = makeModule()
    vi.mocked(createCcWasmModule).mockImplementation(
      async (options: { locateFile: (file: string) => string }) => {
        expect(options.locateFile('cc_client.wasm')).toBe('/wasm/cc_client.wasm')
        return module
      },
    )
    await installWasmCredentialProvider()
    expect(window.cryptoCampusCredentialProvider).toBeDefined()
  })
})

function uuidBytesForTest(value: string): Uint8Array {
  const compact = value.replaceAll('-', '')
  return Uint8Array.from(compact.match(/../g)!.map((pair) => Number.parseInt(pair, 16)))
}
