"""FastAPI dependencies for permission enforcement.

`get_current_user_id` resolves the authenticated principal from the request,
returning ``None`` when no principal is present (anonymous access). A missing
``X-User-Id`` header is therefore *not* an authentication error: a permission
defined with ``user_id IS NULL`` (an anonymous grant) may still authorize the
request. Until a real auth/session layer lands (AGENTS.md §9), the user id is
read from the ``X-User-Id`` header — a placeholder that makes the permission
flow testable end-to-end without a session implementation.

`require_permission` is the centralized permission checker every protected
endpoint depends on. It calls
:meth:`PermissionService.get_effective_filter` and returns the resulting
:class:`SearchFilter` (scoped to the resource); when no grant applies it
returns ``None``, which the dependency converts into a 403 (AGENTS.md §9 —
authorization checks live in services, defense in depth). The returned filter is
applied by services to search/update/delete SQL and validated against incoming
create payloads.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.db import get_session
from ohev.permission.permission_models import Action, ResourceType
from ohev.permission.permission_service import PermissionService
from ohev.util.search_filter import SearchFilter

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_current_user_id(
    x_user_id: Annotated[str | None, Header()] = None,
) -> uuid.UUID | None:
    """Resolve the current user id from the request, or ``None`` if anonymous.

    A missing header means anonymous access (permissions with ``user_id IS
    NULL`` may still apply). A malformed header is a 401: the client claimed to
    present a principal but the value was not a valid UUID.
    """
    if x_user_id is None:
        return None
    try:
        return uuid.UUID(x_user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-User-Id header; expected a UUID.",
        ) from exc


CurrentUserId = Annotated[uuid.UUID | None, Depends(get_current_user_id)]


def require_permission(
    action: Action,
    resource_type: ResourceType,
) -> Callable[..., Coroutine[Any, Any, SearchFilter[Any]]]:
    """Build a FastAPI dependency that checks *action* on *resource_type*.

    Usage::

        @router.get("")
        async def search_users(
            perm_filter: SearchFilter[User] = Depends(
                require_permission(Action.SEARCH, ResourceType.USER)
            ),
            ...,
        ): ...

    Returns the effective :class:`SearchFilter` (scoped to the resource) so
    services can filter search/update/delete SQL and validate creates. Raises
    403 Forbidden when no grant applies (the checker returned ``None``).
    """

    async def _guard(
        session: SessionDep,
        user_id: CurrentUserId,
    ) -> SearchFilter[Any]:
        service = PermissionService(session)
        effective = await service.get_effective_filter(user_id, action, resource_type)
        if effective is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Permission denied: action={action.value} resource_type={resource_type.value}"
                ),
            )
        return effective

    return _guard
