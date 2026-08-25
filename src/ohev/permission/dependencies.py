"""FastAPI dependencies for permission enforcement.

`get_current_user_id` resolves the authenticated principal from the request.
Until a real auth/session layer lands (AGENTS.md §9), the user id is read from
the `X-User-Id` header — a placeholder that makes the permission flow testable
end-to-end without a session implementation.

`require_permission` is the guard every protected endpoint depends on. It
combines the config-level baseline (checked in-memory) with a single SQL query
against the per-user permissions table (AGENTS.md §9 — authorization checks
live in services, defense in depth).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.db import get_session
from ohev.permission.models.permission import Action, ResourceType
from ohev.permission.services import PermissionService

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user_id(
    x_user_id: Annotated[str | None, Header()] = None,
) -> uuid.UUID:
    """Resolve the current user id from the request.

    Placeholder for a real session/JWT extractor (AGENTS.md §9). Reads the
    `X-User-Id` header so the permission flow is testable end-to-end.
    """
    if x_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-User-Id header",
        )
    try:
        return uuid.UUID(x_user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-User-Id header; expected a UUID.",
        ) from exc


CurrentUserId = Annotated[uuid.UUID, Depends(get_current_user_id)]


def require_permission(
    action: Action,
    resource_type: ResourceType,
) -> Callable[..., Coroutine[Any, Any, None]]:
    """Build a FastAPI dependency that enforces *action* on *resource_type*.

    Usage::

        @router.get(
            "",
            dependencies=[Depends(require_permission(Action.SEARCH, ResourceType.USER))],
        )
        async def search_users(...): ...

    Raises 403 Forbidden when the principal is not granted the requested
    action. Depends on the DB session and the current user id.
    """

    async def _guard(
        session: SessionDep,
        user_id: CurrentUserId,
    ) -> None:
        service = PermissionService(session)
        allowed = await service.check_permission(user_id, action, resource_type)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Permission denied: action={action.value} resource_type={resource_type.value}"
                ),
            )

    return _guard
