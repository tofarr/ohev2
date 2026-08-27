"""FastAPI dependencies for permission enforcement.

`require_permission` is the centralized permission checker every protected
endpoint depends on. It calls
:meth:`PermissionService.get_effective_filter` and returns the resulting
:class:`SearchFilter` (scoped to the resource); when no grant applies it
returns ``None``, which the dependency converts into a 403 (AGENTS.md §9 —
authorization checks live in services, defense in depth). The returned filter is
applied by services to search/update/delete SQL and validated against incoming
create payloads.

Principal resolution (the ``X-API-Key`` / ``Authorization: Bearer`` / cookie
lookup and JWE decryption) lives in :mod:`openhands.ev2.auth.auth_dependencies` so the
auth package owns all credential handling; this module consumes
``CurrentUserId`` from there.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import HTTPException, status

from openhands.ev2.auth.auth_dependencies import CurrentUserId
from openhands.ev2.db import SessionDep
from openhands.ev2.permission.permission_models import Action, ResourceType
from openhands.ev2.permission.permission_service import PermissionService
from openhands.ev2.util.search_filter import SearchFilter


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
