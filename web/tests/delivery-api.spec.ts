import { describe, expect, it } from 'vitest'

import {
  destroyDrop,
  exportAdminAudit,
  flagVoteForAudit,
  listAdminUsers,
  resetUserQuotas,
  updateUserRole,
  updateUserStatus,
  withdrawHolePost,
} from '@/api/admin'
import {
  createHoleComment,
  createHoleCommitment,
  createHolePost,
  issueHoleCredential,
  likeHolePost,
  listHoleComments,
  verifyHoleCredential,
} from '@/api/hole'
import { deleteAccount, exportKeyringBackup, importKeyringBackup } from '@/api/me'
import { issueVoteCredential, submitBallot } from '@/api/votes'
import { installApiMock, jsonResponse } from './support/api'

const proof = { sn: 'sn-1', service: 'hole_post', period: '2026-09-10', signature: 'sig' }
const user = {
  id: 'user-1', email: 'u@example.edu.cn', role: 'student', status: 'active', pqc_mode: false,
  created_at: '2026-09-10T00:00:00Z',
}

describe('交付补齐 API 客户端', () => {
  it('按契约封装树洞凭证、发布、评论、点赞和公开验签', async () => {
    const fetchMock = installApiMock({
      '/api/v1/hole/credentials/commitments': jsonResponse({
        commitment_id: '11223344556677889900aabbccddeeff',
        commitment_point: 'BMabc',
        expires_at: '2026-09-10T12:00:00Z',
        algorithm: 'SM2-BLIND-PROTOCOL-V1',
      }, 201),
      '/api/v1/hole/credentials': jsonResponse({ blind_signature: 'blind', algorithm: 'SM2-BLIND-PROTOCOL-V1' }, 201),
      '/api/v1/hole/posts': jsonResponse({ id: 'post-1' }, 201),
      '/api/v1/hole/credentials/verify': jsonResponse({ valid: true }),
      '/api/v1/hole/posts/post-1/comments?page=1&page_size=20': jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }),
      '/api/v1/hole/posts/post-1/comments': jsonResponse({ id: 'comment-1' }, 201),
      '/api/v1/hole/posts/post-1/likes': jsonResponse({ accepted: true }, 201),
    })
    await createHoleCommitment({ service: 'hole_post', period: '2026-09-10' }, 'token')
    await issueHoleCredential({ service: 'hole_post', period: '2026-09-10', blinded_message: 'blind' }, 'token', 'i1')
    await createHolePost({ content: 'hello', credential: proof }, 'token', 'i2')
    await verifyHoleCredential(proof)
    await listHoleComments('post-1')
    await createHoleComment('post-1', { content: 'reply', credential: proof }, 'i3')
    await likeHolePost('post-1', proof, 'i4')
    expect(fetchMock).toHaveBeenCalledTimes(7)
  })

  it('按契约封装投票凭证和匿名选票', async () => {
    const fetchMock = installApiMock({
      '/api/v1/votes/vote-1/credentials': jsonResponse({ blind_signature: 'blind', algorithm: 'SM2-BLIND-PROTOCOL-V1' }, 201),
      '/api/v1/votes/vote-1/ballots': jsonResponse({ accepted: true }, 201),
    })
    await issueVoteCredential('vote-1', { service: 'vote_ballot', period: 'vote-1', blinded_message: 'blind' }, 'token', 'i1')
    await submitBallot('vote-1', { option_id: 'option-1', credential: { ...proof, service: 'vote_ballot', period: 'vote-1' } }, 'i2')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('按契约封装备份和账号注销', async () => {
    const fetchMock = installApiMock({
      '/api/v1/me/keyring/export': new Response('PEM', { headers: { 'Content-Type': 'application/x-pem-file' } }),
      '/api/v1/me/keyring/import': jsonResponse({ items: [], unlocked_until: null }),
      '/api/v1/me/account': jsonResponse({ accepted: true }, 202),
    })
    await exportKeyringBackup({ password: 'BackupPassword1' }, 'token')
    await importKeyringBackup(new File(['PEM'], 'backup.pem'), 'BackupPassword1', 'token')
    await deleteAccount({ password: 'Password1', confirm: 'DELETE_MY_ACCOUNT' }, 'token')
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls[1][1]?.body).toBeInstanceOf(FormData)
  })

  it('按契约封装账号与内容治理以及审计导出', async () => {
    const fetchMock = installApiMock({
      '/api/v1/admin/users?page=1&page_size=20': jsonResponse({ items: [user], page: 1, page_size: 20, total: 1 }),
      '/api/v1/admin/users/user-1/status': jsonResponse({ ...user, status: 'frozen' }),
      '/api/v1/admin/users/user-1/role': jsonResponse({ ...user, role: 'teacher' }),
      '/api/v1/admin/users/user-1/quotas/reset': jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }),
      '/api/v1/admin/hole/posts/post-1/withdraw': jsonResponse({ sn: 'sn' }),
      '/api/v1/admin/drops/drop-1/destroy': new Response(null, { status: 204 }),
      '/api/v1/admin/votes/vote-1/audit-flags': jsonResponse({ accepted: true }, 201),
      '/api/v1/admin/audit/export?format=csv': new Response('action,target'),
    })
    await listAdminUsers('token')
    await updateUserStatus('user-1', { status: 'frozen', reason: 'review' }, 'token')
    await updateUserRole('user-1', { role: 'teacher', reason: 'approved' }, 'token')
    await resetUserQuotas('user-1', 'token', 'i1')
    await withdrawHolePost('post-1', 'policy', 'token')
    await destroyDrop('drop-1', 'token')
    await flagVoteForAudit('vote-1', 'review', 'token')
    await exportAdminAudit('csv', 'token')
    expect(fetchMock).toHaveBeenCalledTimes(8)
  })
})
