from collections.abc import Sequence

from fastapi import APIRouter, Depends

from app.core.errors import ApiError
from app.security.auth_dependencies import require_roles


# The canonical OpenAPI document describes the whole course target. Operations in
# this registry are intentionally unavailable until their owning feature lands.
# Registering explicit fail-closed placeholders prevents a missing backend route
# from being mistaken for a successful implementation or an unknown resource.
NOT_IMPLEMENTED_OPERATIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("PATCH", "/me/pqc-mode", ("student", "admin", "teacher")),
    ("POST", "/admin/fair-blind/reveal-requests", ("admin", "teacher")),
    (
        "POST",
        "/admin/fair-blind/reveal-requests/{reveal_request_id}/approve",
        ("admin", "teacher"),
    ),
)


async def _not_implemented() -> None:
    raise ApiError(501, "NOT_IMPLEMENTED", "此功能暂未开放")


def _dependencies(roles: Sequence[str]) -> list[object]:
    if "guest" in roles:
        return []
    return [Depends(require_roles(*roles))]


router = APIRouter()
for _method, _path, _roles in NOT_IMPLEMENTED_OPERATIONS:
    router.add_api_route(
        _path,
        _not_implemented,
        methods=[_method],
        dependencies=_dependencies(_roles),
        include_in_schema=False,
        name=f"not_implemented_{_method.lower()}_{_path}",
    )
