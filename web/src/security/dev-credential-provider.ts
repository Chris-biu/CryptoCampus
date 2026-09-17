/* global crypto, btoa */
import type { BlindCommitmentResponse, BlindCredentialResponse, CredentialProof } from '@/api/hole'
import type { AnonymousService, CryptoCampusCredentialProvider } from './credential-provider'

function randomHex(byteLength: number): string {
  const buf = new Uint8Array(byteLength)
  crypto.getRandomValues(buf)
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function createDevCredentialProvider(): CryptoCampusCredentialProvider {
  return {
    async blind({ service, period, commitment }: {
      service: AnonymousService
      period: string
      commitment?: BlindCommitmentResponse
    }) {
      const sn = randomHex(16) // 32 hex chars = 16 bytes
      let blindedMessage: string

      if (commitment) {
        // ADR-0001 Round 2: 16B commitment_id || 32B c' = 48B payload
        const cidBytes = hexToBytes(commitment.commitment_id)
        const cPrime = new Uint8Array(32)
        crypto.getRandomValues(cPrime)
        const payload = new Uint8Array(cidBytes.length + cPrime.length)
        payload.set(cidBytes, 0)
        payload.set(cPrime, cidBytes.length)
        blindedMessage = bytesToBase64(payload)
      } else {
        const raw = new Uint8Array(32)
        crypto.getRandomValues(raw)
        blindedMessage = bytesToBase64(raw)
      }

      return {
        blindedMessage,
        state: { sn, service, period },
      }
    },

    async unblind({ service, period, response, state }: {
      service: AnonymousService
      period: string
      response: BlindCredentialResponse
      state: unknown
    }): Promise<CredentialProof> {
      const s = state as { sn: string; service: string; period: string } | null
      return {
        sn: s?.sn || randomHex(16),
        service,
        period,
        signature: response.blind_signature,
      }
    },
  }
}

export function installDevCredentialProvider(): void {
  window.cryptoCampusCredentialProvider = createDevCredentialProvider()
}

export function uninstallDevCredentialProvider(): void {
  delete window.cryptoCampusCredentialProvider
}
