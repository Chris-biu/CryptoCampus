import { apiClient } from './client'
import type { components, operations } from './schema'

export type HolePost = components['schemas']['HolePost']
export type HolePostPage = components['schemas']['HolePostPage']
export type HoleComment = components['schemas']['HoleComment']
export type HoleCommentPage = components['schemas']['HoleCommentPage']
export type CredentialProof = components['schemas']['CredentialProof']
export type CredentialVerification = components['schemas']['CredentialVerification']
export type BlindCredentialRequest = components['schemas']['BlindCredentialRequest']
export type BlindCredentialResponse = components['schemas']['BlindCredentialResponse']
export type BlindCommitmentRequest = components['schemas']['BlindCommitmentRequest']
export type BlindCommitmentResponse = components['schemas']['BlindCommitmentResponse']

export function createHoleCommitment(
  request: BlindCommitmentRequest,
  accessToken: string,
): Promise<BlindCommitmentResponse> {
  return apiClient.post<BlindCommitmentResponse>('/hole/credentials/commitments', {
    accessToken,
    body: request,
  })
}
export type CreateHolePostRequest =
  operations['createHolePost']['requestBody']['content']['application/json']
export type CreateHoleCommentRequest =
  operations['createHoleComment']['requestBody']['content']['application/json']

export function listHolePosts(page = 1, pageSize = 10): Promise<HolePostPage> {
  return apiClient.get<HolePostPage>('/hole/posts', {
    query: { page, page_size: pageSize },
  })
}

export function issueHoleCredential(
  request: BlindCredentialRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<BlindCredentialResponse> {
  return apiClient.post<BlindCredentialResponse>('/hole/credentials', {
    accessToken,
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function createHolePost(
  request: CreateHolePostRequest,
  accessToken: string,
  idempotencyKey: string,
): Promise<HolePost> {
  return apiClient.post<HolePost>('/hole/posts', {
    accessToken,
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function verifyHoleCredential(
  credential: CredentialProof,
): Promise<CredentialVerification> {
  return apiClient.post<CredentialVerification>('/hole/credentials/verify', {
    body: credential,
  })
}

export function listHoleComments(
  postId: string,
  page = 1,
  pageSize = 20,
): Promise<HoleCommentPage> {
  return apiClient.get<HoleCommentPage>('/hole/posts/{post_id}/comments', {
    pathParams: { post_id: postId },
    query: { page, page_size: pageSize },
  })
}

export function createHoleComment(
  postId: string,
  request: CreateHoleCommentRequest,
  idempotencyKey: string,
): Promise<HoleComment> {
  return apiClient.post<HoleComment>('/hole/posts/{post_id}/comments', {
    pathParams: { post_id: postId },
    body: request,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function likeHolePost(
  postId: string,
  credential: CredentialProof,
  idempotencyKey: string,
): Promise<components['schemas']['Accepted']> {
  return apiClient.post<components['schemas']['Accepted']>('/hole/posts/{post_id}/likes', {
    pathParams: { post_id: postId },
    body: { credential },
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}
