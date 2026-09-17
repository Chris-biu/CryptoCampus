import { apiClient } from './client'
import type { components, operations } from './schema'

export type Vote = components['schemas']['Vote']
export type VotePage = components['schemas']['VotePage']
export type VoteResult = components['schemas']['VoteResult']
export type VoteAuditReport = components['schemas']['VoteAuditReport']
export type SignatureVerification = components['schemas']['SignatureVerification']
export type CredentialProof = components['schemas']['CredentialProof']
export type BlindCredentialRequest = components['schemas']['BlindCredentialRequest']
export type BlindCredentialResponse = components['schemas']['BlindCredentialResponse']
export type BlindCommitmentResponse = components['schemas']['BlindCommitmentResponse']
export type SubmitBallotRequest =
  operations['submitBallot']['requestBody']['content']['application/json']
export type CreateVoteRequest =
  operations['createVote']['requestBody']['content']['application/json']

export function listVotes(page = 1, pageSize = 20): Promise<VotePage> {
  return apiClient.get<VotePage>('/votes', { query: { page, page_size: pageSize } })
}

export function createVote(
  request: CreateVoteRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<Vote> {
  return apiClient.post<Vote>('/votes', {
    accessToken,
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function issueVoteCredential(
  voteId: string,
  request: BlindCredentialRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<BlindCredentialResponse> {
  return apiClient.post<BlindCredentialResponse>('/votes/{vote_id}/credentials', {
    accessToken,
    pathParams: { vote_id: voteId },
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function createVoteCommitment(
  voteId: string,
  accessToken: string,
): Promise<BlindCommitmentResponse> {
  return apiClient.post<BlindCommitmentResponse>('/votes/{vote_id}/credentials/commitments', {
    accessToken,
    pathParams: { vote_id: voteId },
    body: { service: 'vote_ballot', period: voteId },
  })
}

export function submitBallot(
  voteId: string,
  request: SubmitBallotRequest,
  idempotencyKey: string,
): Promise<components['schemas']['Accepted']> {
  return apiClient.post<components['schemas']['Accepted']>('/votes/{vote_id}/ballots', {
    pathParams: { vote_id: voteId },
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function getVoteResults(voteId: string): Promise<VoteResult> {
  return apiClient.get<VoteResult>('/votes/{vote_id}/results', {
    pathParams: { vote_id: voteId },
  })
}

export function verifyVoteResult(voteId: string): Promise<SignatureVerification> {
  return apiClient.get<SignatureVerification>('/votes/{vote_id}/results/verify', {
    pathParams: { vote_id: voteId },
  })
}

export function exportVoteAudit(voteId: string): Promise<VoteAuditReport> {
  return apiClient.get<VoteAuditReport>('/votes/{vote_id}/audit', {
    pathParams: { vote_id: voteId },
  })
}
