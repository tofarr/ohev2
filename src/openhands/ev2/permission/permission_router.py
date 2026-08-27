"""HTTP routes for the permission feature.

Uniform REST surface (AGENTS.md §3). Supports filtering the collection by user
via `?user_id=…` — a query param on the collection, never a bespoke route.
Every endpoint is guarded by the centralized permission checker
(AGENTS.md §9); the returned :class:`SearchFilter` is passed into the service
constructor so search/delete SQL and create payloads are scoped to the
principal. Permissions are immutable, so there is no PATCH/UPDATE endpoint —
delete and re-create.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.db import SessionDep
from openhands.ev2.permission.permission_dependencies import require_permission
from openhands.ev2.permission.permission_models import Action, ResourceType
from openhands.ev2.permission.permission_schemas import (
    PermissionCreate,
    PermissionRead,
    PermissionSearchFilter,
    PermissionSearchResult,
)
from openhands.ev2.permission.permission_service import (
    PermissionConflictError,
    PermissionNotFoundError,
    PermissionScopeError,
    PermissionService,
)
from openhands.ev2.util.schemas import CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/permissions", tags=["permissions"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get(
    "",
    response_model=PermissionSearchResult,
)
async def search_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(require_permission(Action.SEARCH, ResourceType.PERMISSION))
    ],
    # See user router: bare `Depends()` is required so FastAPI explodes the
    # filter model's fields as individual query params alongside scalar queries.
    search_filter: PermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> PermissionSearchResult:
    service = PermissionService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    permissions, next_cursor = await service.search_permissions(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return PermissionSearchResult(
        items=[PermissionRead.model_validate(p) for p in permissions],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get(
    "/count",
    response_model=CountResult,
)
async def count_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(require_permission(Action.SEARCH, ResourceType.PERMISSION))
    ],
    # See search_permissions: bare `Depends()` lets FastAPI explode the filter
    # model's fields as query params. Declared before `/{permission_id}` so the
    # static path matches ahead of the UUID path param.
    search_filter: PermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = PermissionService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "",
    response_model=PermissionRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_permission(
    payload: PermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(require_permission(Action.CREATE, ResourceType.PERMISSION))
    ],
) -> PermissionRead:
    service = PermissionService(session, perm_filter)
    try:
        permission = await service.create(payload)
    except PermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission falls outside your create scope: {exc}",
        ) from exc
    except PermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission already exists: {exc}",
        ) from exc
    await session.commit()
    return PermissionRead.model_validate(permission)


@router.get(
    "/{permission_id}",
    response_model=PermissionRead,
)
async def get_permission(
    permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(require_permission(Action.READ, ResourceType.PERMISSION))
    ],
) -> PermissionRead:
    service = PermissionService(session, perm_filter)
    try:
        permission = await service.get(permission_id)
    except PermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission not found: {exc}",
        ) from exc
    return PermissionRead.model_validate(permission)


@router.delete(
    "/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_permission(
    permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(require_permission(Action.DELETE, ResourceType.PERMISSION))
    ],
) -> None:
    service = PermissionService(session, perm_filter)
    try:
        await service.delete(permission_id)
    except PermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission not found: {exc}",
        ) from exc
    await session.commit()
