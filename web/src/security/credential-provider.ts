import { ApiError } from '@/api/errors'
import type { BlindCommitmentResponse, BlindCredentialResponse, CredentialProof } from '@/api/hole'

export type AnonymousService = 'hole_post' | 'hole_comment' | 'hole_like' | 'vote_ballot'

export interface BlindCredentialDraft {
  blindedMessage: string
  state: unknown
}

export interface CryptoCampusCredentialProvider {
  blind(input: {
    service: AnonymousService
    period: string
    commitment: BlindCommitmentResponse
    context?: string
  }): Promise<BlindCredentialDraft>
  unblind(input: {
    service: AnonymousService
    period: string
    response: BlindCredentialResponse
    state: unknown
  }): Promise<CredentialProof>
}

declare global {
  interface Window {
    cryptoCampusCredentialProvider?: CryptoCampusCredentialProvider
  }
}

function providerError(code: 'CRYPTO_CLIENT_UNAVAILABLE' | 'CRYPTO_CLIENT_INVALID'): ApiError {
  return new ApiError({ code, status: 0 })
}

function validProof(
  value: unknown,
  service: AnonymousService,
  period: string,
): value is CredentialProof {
  if (!value || typeof value !== 'object') return false
  const proof = value as Partial<CredentialProof>
  return (
    typeof proof.sn === 'string' &&
    proof.sn.length > 0 &&
    proof.service === service &&
    proof.period === period &&
    typeof proof.signature === 'string' &&
    proof.signature.length > 0
  )
}

export function hasCredentialProvider(): boolean {
  return Boolean(window.cryptoCampusCredentialProvider)
}

export async function acquireCredential(
  service: AnonymousService,
  period: string,
  issue: (blindedMessage: string) => Promise<BlindCredentialResponse>,
  getCommitment: () => Promise<BlindCommitmentResponse>,
  context?: string,
): Promise<CredentialProof> {
  const provider = window.cryptoCampusCredentialProvider
  if (!provider) throw providerError('CRYPTO_CLIENT_UNAVAILABLE')

  const commitment = await getCommitment()
  const draft = await provider.blind({ service, period, commitment, context })
  if (!draft?.blindedMessage) throw providerError('CRYPTO_CLIENT_INVALID')
  const response = await issue(draft.blindedMessage)
  const proof = await provider.unblind({ service, period, response, state: draft.state })
  if (!validProof(proof, service, period)) throw providerError('CRYPTO_CLIENT_INVALID')
  return proof
}

export function currentCredentialPeriod(now = new Date()): string {
  return now.toISOString().slice(0, 10)
}

export {
  createDevCredentialProvider,
  installDevCredentialProvider,
  uninstallDevCredentialProvider,
} from './dev-credential-provider'
