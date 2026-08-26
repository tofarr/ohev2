"""FastAPI dependencies for permission enforcement.

`get_current_user_id` resolves the authenticated principal from the request,
returning ``None`` when no principal is present (anonymous access). The
principal is read from a JWE-encrypted auth token supplied via, in order:

1. the ``X-API-Key`` header (an encrypted auth token, not a raw id),
2. the ``Authorization: Bearer <token>`` header, or
3. the ``session`` cookie set by the login endpoint.

A token that is missing entirely means anonymous access (permissions with
``user_id IS NULL`` may still apply). A *present but invalid/expired* token is a
401: the client claimed a principal but the credential was bad. The token is
decrypted with the EncryptionService; the user id is opaque to clients
(AGENTS.md §9).

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

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.config import get_config
from ohev.db import get_session
from ohev.permission.permission_models import Action, ResourceType
from ohev.permission.permission_service import PermissionService
from ohev.util.auth_token import extract_user_id
from ohev.util.search_filter import SearchFilter

SessionDep = Annotated[AsyncSession, Depends(get_session)]


def _resolve_token_from_request(
    x_api_key: str | None,
    authorization: str | None,
    request: Request,
) -> str | None:
    """Pick the auth token from the first present source, in priority order."""
    if x_api_key is not None:
        return x_api_key
    if authorization is not None:
        # Accept "Bearer <token>"; tolerate a bare token for robustness.
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token
        return authorization
    cookie_name = get_config().auth_cookie_name
    return request.cookies.get(cookie_name)


async def get_current_user_id(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> uuid.UUID | None:
    """Resolve the current user id from an encrypted auth token, or ``None``.

    Checks the ``X-API-Key`` header first, then the ``Authorization: Bearer``
    header, then the session cookie. A missing token means anonymous access; a
    present-but-invalid token is a 401.
    """
    token = _resolve_token_from_request(x_api_key, authorization, request)
    if token is None:
        return None
    user_id = extract_user_id(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired auth token.",
        )
    return user_id


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
