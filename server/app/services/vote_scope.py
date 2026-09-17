from typing import Optional, Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.vote import VoteRecord, VoteScopeMember, VoteScopeUnit


class VoteScopeError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


@runtime_checkable
class VoteScopePolicy(Protocol):
    def require_can_create(
        self, *, user_id: str, scope: str, scope_id: Optional[str]
    ) -> None: ...
    def require_can_issue(self, *, user_id: str, vote_id: str) -> None: ...


@runtime_checkable
class ScopeMembershipProvider(Protocol):
    def get_scope(self, *, scope_id: str) -> Optional[VoteScopeUnit]: ...
    def is_member(self, *, user_id: str, scope_id: str) -> bool: ...


class DatabaseScopeMembershipProvider:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_scope(self, *, scope_id: str) -> Optional[VoteScopeUnit]:
        return self.session.get(VoteScopeUnit, scope_id)

    def is_member(self, *, user_id: str, scope_id: str) -> bool:
        statement = select(VoteScopeMember.id).where(
            VoteScopeMember.user_id == user_id,
            VoteScopeMember.scope_id == scope_id,
        )
        return self.session.scalar(statement) is not None


class DefaultVoteScopePolicy:
    def __init__(
        self,
        session: Session,
        membership_provider: Optional[ScopeMembershipProvider] = None,
    ) -> None:
        self.session = session
        self.membership_provider = membership_provider or DatabaseScopeMembershipProvider(session)

    def require_can_create(
        self, *, user_id: str, scope: str, scope_id: Optional[str]
    ) -> None:
        self._require_active_eligible_user(user_id=user_id, action="创建投票")
        if scope == "public":
            if scope_id is not None:
                raise VoteScopeError("scope_id_forbidden", "public 范围不应携带 scope_id")
            return
        self._require_scope_member(user_id=user_id, scope=scope, scope_id=scope_id)

    def require_can_issue(self, *, user_id: str, vote_id: str) -> None:
        self._require_active_eligible_user(user_id=user_id, action="申领选票凭证")
        vote = self.session.get(VoteRecord, vote_id)
        if vote is None:
            raise VoteScopeError("vote_not_found", "投票不存在")
        if vote.scope == "public":
            return
        self._require_scope_member(
            user_id=user_id,
            scope=vote.scope,
            scope_id=vote.scope_id,
        )

    def _require_active_eligible_user(self, *, user_id: str, action: str) -> None:
        user = self.session.get(User, user_id)
        if user is None or user.status != "active":
            raise VoteScopeError("user_inactive", "用户不存在或状态不可用")
        if user.role not in ("student", "admin", "teacher"):
            raise VoteScopeError("permission_denied", f"角色无权{action}")

    def _require_scope_member(
        self, *, user_id: str, scope: str, scope_id: Optional[str]
    ) -> None:
        if scope not in ("class", "group"):
            raise VoteScopeError("invalid_scope", f"未知投票范围: {scope}")
        if scope_id is None:
            raise VoteScopeError("scope_id_required", f"{scope} 范围必须指定 scope_id")
        unit = self.membership_provider.get_scope(scope_id=scope_id)
        if unit is None:
            raise VoteScopeError("scope_not_found", "指定的投票范围不存在")
        if not unit.active:
            raise VoteScopeError("scope_inactive", "指定的投票范围已停用")
        if unit.kind != scope:
            raise VoteScopeError("scope_kind_mismatch", "scope 与 scope_id 的范围类型不一致")
        if not self.membership_provider.is_member(user_id=user_id, scope_id=scope_id):
            raise VoteScopeError("not_scope_member", "用户不属于指定的投票范围")
