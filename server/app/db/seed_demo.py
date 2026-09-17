"""Manually seed isolated demo scope data for local development only."""

import os
from collections.abc import Mapping

from sqlalchemy.orm import Session

from app.db.session import SessionLocal, engine, init_database
from app.models.user import User
from app.models.vote import VoteScopeMember, VoteScopeUnit


DEMO_CLASS_ID = "10000000-0000-4000-8000-000000000001"
DEMO_GROUP_ID = "20000000-0000-4000-8000-000000000001"

DEMO_SCOPES = (
    (DEMO_CLASS_ID, "class", "演示班级：软件工程 2301"),
    (DEMO_GROUP_ID, "group", "演示群组：密码学兴趣小组"),
)

DEMO_USERS = (
    ("student01@example.edu", "student"),
    ("student02@example.edu", "student"),
    ("teacher01@example.edu", "teacher"),
)


def require_demo_seed_allowed(environ: Mapping[str, str]) -> None:
    environment = environ.get("CRYPTOCAMPUS_ENV", "").strip().lower()
    if environment in {"prod", "production"}:
        raise RuntimeError("生产环境禁止写入演示范围数据")
    if environ.get("CRYPTOCAMPUS_ALLOW_DEMO_SEED") != "1":
        raise RuntimeError("必须显式设置 CRYPTOCAMPUS_ALLOW_DEMO_SEED=1")


def seed_demo_scope_data(session: Session) -> dict[str, int]:
    require_demo_seed_allowed(os.environ)

    users: list[User] = []
    created_users = 0
    for email, role in DEMO_USERS:
        user = session.query(User).filter_by(email=email).one_or_none()
        if user is None:
            user = User(email=email, role=role, status="active")
            session.add(user)
            session.flush()
            created_users += 1
        users.append(user)

    scopes: list[VoteScopeUnit] = []
    created_scopes = 0
    for scope_id, kind, name in DEMO_SCOPES:
        unit = session.get(VoteScopeUnit, scope_id)
        if unit is None:
            unit = VoteScopeUnit(id=scope_id, kind=kind, name=name, active=True)
            session.add(unit)
            session.flush()
            created_scopes += 1
        elif unit.kind != kind:
            raise RuntimeError(f"演示范围 {scope_id} 的 kind 与预期不一致")
        scopes.append(unit)

    created_memberships = 0
    for scope in scopes:
        for user in users:
            exists = (
                session.query(VoteScopeMember)
                .filter_by(scope_id=scope.id, user_id=user.id)
                .one_or_none()
            )
            if exists is None:
                session.add(VoteScopeMember(scope_id=scope.id, user_id=user.id))
                created_memberships += 1

    session.commit()
    return {
        "users": created_users,
        "scopes": created_scopes,
        "memberships": created_memberships,
    }


def main() -> None:
    init_database(engine)
    with SessionLocal() as session:
        result = seed_demo_scope_data(session)
    print(
        "演示范围数据写入完成："
        f"users={result['users']}, scopes={result['scopes']}, "
        f"memberships={result['memberships']}"
    )


if __name__ == "__main__":
    main()
