/* global atob, btoa, crypto */
import type { BlindCommitmentResponse, BlindCredentialResponse, CredentialProof } from '@/api/hole'
import type { CryptoCampusCredentialProvider } from './credential-provider'
import createCcWasmModule from './cc-client.generated.js'

interface CcWasmModule {
  HEAPU8: Uint8Array
  _malloc(size: number): number
  _free(pointer: number): void
  _cc_client_scalar_is_valid(scalar: number): number
  _cc_client_blind(
    pk: number,
    commitment: number,
    message: number,
    messageLength: number,
    alpha: number,
    beta: number,
    cPrime: number,
    state: number,
    rPrime: number,
  ): number
  _cc_client_unblind(sPrime: number, state: number, output: number): number
  _cc_client_credential(rPrime: number, s: number, output: number): number
}

interface WasmCredentialState {
  sn: Uint8Array
  blindState: Uint8Array
  rPrime: Uint8Array
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function encodeBase64(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function decodeHex(value: string, expectedLength: number): Uint8Array {
  if (!new RegExp(`^[0-9a-fA-F]{${expectedLength * 2}}$`).test(value))
    throw new Error('invalid hex')
  return Uint8Array.from({ length: expectedLength }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  )
}

function encodeHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function uuidBytes(value: string): Uint8Array {
  const compact = value.replaceAll('-', '')
  return decodeHex(compact, 16)
}

function credentialMessage(
  sn: Uint8Array,
  service: string,
  period: string,
  context?: string,
): Uint8Array {
  const encoder = new TextEncoder()
  if (service === 'vote_ballot') {
    if (!context) throw new Error('vote option binding unavailable')
    const domain = encoder.encode('CryptoCampus-Vote-Ballot-v1\0')
    const serviceBytes = encoder.encode(service)
    const message = new Uint8Array(domain.length + sn.length + 2 + serviceBytes.length + 16 + 16)
    let offset = 0
    message.set(domain, offset)
    offset += domain.length
    message.set(sn, offset)
    offset += sn.length
    message[offset] = (serviceBytes.length >>> 8) & 0xff
    message[offset + 1] = serviceBytes.length & 0xff
    offset += 2
    message.set(serviceBytes, offset)
    offset += serviceBytes.length
    message.set(uuidBytes(period), offset)
    offset += 16
    message.set(uuidBytes(context), offset)
    return message
  }
  return new Uint8Array([...sn, ...encoder.encode(service), ...encoder.encode(period)])
}

function randomScalar(module: CcWasmModule): Uint8Array {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    const value = crypto.getRandomValues(new Uint8Array(32))
    const pointer = module._malloc(32)
    try {
      module.HEAPU8.set(value, pointer)
      if (module._cc_client_scalar_is_valid(pointer) === 1) return value
    } finally {
      module.HEAPU8.fill(0, pointer, pointer + 32)
      module._free(pointer)
    }
  }
  throw new Error('unable to sample scalar')
}

function withBuffers<T>(module: CcWasmModule, sizes: number[], run: (pointers: number[]) => T): T {
  const pointers = sizes.map((size) => module._malloc(size))
  try {
    return run(pointers)
  } finally {
    sizes.forEach((size, index) => {
      module.HEAPU8.fill(0, pointers[index], pointers[index] + size)
      module._free(pointers[index])
    })
  }
}

function requireCommitment(
  value: BlindCommitmentResponse | undefined,
): BlindCommitmentResponse & { signer_public_key: string } {
  if (!value || typeof value.signer_public_key !== 'string')
    throw new Error('blind commitment unavailable')
  return value as BlindCommitmentResponse & { signer_public_key: string }
}

export function createWasmCredentialProvider(module: CcWasmModule): CryptoCampusCredentialProvider {
  return {
    async blind({ service, period, commitment, context }) {
      const server = requireCommitment(commitment)
      const commitmentId = decodeHex(server.commitment_id, 16)
      const point = decodeBase64(server.commitment_point)
      const publicKey = decodeBase64(server.signer_public_key)
      if (
        point.length !== 65 ||
        point[0] !== 0x04 ||
        publicKey.length !== 65 ||
        publicKey[0] !== 0x04
      )
        throw new Error('invalid SM2 point')
      const sn = crypto.getRandomValues(new Uint8Array(16))
      const message = credentialMessage(sn, service, period, context)
      const alpha = randomScalar(module)
      const beta = randomScalar(module)
      try {
        return withBuffers(module, [65, 65, message.length, 32, 32, 32, 64, 65], (p) => {
          module.HEAPU8.set(publicKey, p[0])
          module.HEAPU8.set(point, p[1])
          module.HEAPU8.set(message, p[2])
          module.HEAPU8.set(alpha, p[3])
          module.HEAPU8.set(beta, p[4])
          const result = module._cc_client_blind(
            p[0],
            p[1],
            p[2],
            message.length,
            p[3],
            p[4],
            p[5],
            p[6],
            p[7],
          )
          if (result !== 0) throw new Error(`cc_client_blind failed: ${result}`)
          const cPrime = module.HEAPU8.slice(p[5], p[5] + 32)
          const blindState = module.HEAPU8.slice(p[6], p[6] + 64)
          const rPrime = module.HEAPU8.slice(p[7], p[7] + 65)
          const payload = new Uint8Array(48)
          payload.set(commitmentId)
          payload.set(cPrime, 16)
          return {
            blindedMessage: encodeBase64(payload),
            state: { sn, blindState, rPrime } satisfies WasmCredentialState,
          }
        })
      } finally {
        alpha.fill(0)
        beta.fill(0)
        message.fill(0)
      }
    },

    async unblind({ service, period, response, state }): Promise<CredentialProof> {
      const local = state as WasmCredentialState | undefined
      const sPrime = decodeBase64((response as BlindCredentialResponse).blind_signature)
      if (
        !local ||
        local.sn.length !== 16 ||
        local.blindState.length !== 64 ||
        local.rPrime.length !== 65 ||
        sPrime.length !== 32
      )
        throw new Error('invalid blind-signature state')
      try {
        return withBuffers(module, [32, 64, 32, 65, 64], (p) => {
          module.HEAPU8.set(sPrime, p[0])
          module.HEAPU8.set(local.blindState, p[1])
          if (module._cc_client_unblind(p[0], p[1], p[2]) !== 0)
            throw new Error('cc_client_unblind failed')
          module.HEAPU8.set(local.rPrime, p[3])
          if (module._cc_client_credential(p[3], p[2], p[4]) !== 0)
            throw new Error('cc_client_credential failed')
          return {
            sn: encodeHex(local.sn),
            service,
            period,
            signature: encodeBase64(module.HEAPU8.slice(p[4], p[4] + 64)),
          }
        })
      } finally {
        sPrime.fill(0)
        local.sn.fill(0)
        local.blindState.fill(0)
        local.rPrime.fill(0)
      }
    },
  }
}

export async function installWasmCredentialProvider(): Promise<void> {
  const module = (await createCcWasmModule({
    locateFile: (file: string) => `/wasm/${file}`,
  })) as CcWasmModule
  window.cryptoCampusCredentialProvider = createWasmCredentialProvider(module)
}
