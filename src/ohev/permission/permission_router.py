"""HTTP routes for the permission feature.

Uniform REST surface (AGENTS.md §3). Supports filtering the collection by user
via `?user_id=…` — a query param on the collection, never a bespoke route.
Every endpoint is guarded by a permission check (AGENTS.md §9). Permissions are
immutable, so there is no PATCH/UPDATE endpoint — delete and re-create.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ohev.permission.permission_dependencies import (
    SessionDep,
    require_permission,
)
from ohev.permission.permission_models import Action, ResourceType
from ohev.permission.permission_schemas import (
    PermissionCreate,
    PermissionRead,
    PermissionSearchFilter,
    PermissionSearchResult,
)
from ohev.permission.permission_service import (
    PermissionConflictError,
    PermissionNotFoundError,
    PermissionService,
)

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
    dependencies=[Depends(require_permission(Action.SEARCH, ResourceType.PERMISSION))],
)
async def search_permissions(
    session: SessionDep,
    # See user router: bare `Depends()` is required so FastAPI explodes the
    # filter model's fields as individual query params alongside scalar queries.
    search_filter: PermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> PermissionSearchResult:
    service = PermissionService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    permissions, next_cursor = await service.search_permissions(
        cursor=cursor_uuid, limit=limit, search_filter=search_filter
    )
    return PermissionSearchResult(
        items=[PermissionRead.model_validate(p) for p in permissions],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post(
    "",
    response_model=PermissionRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Action.CREATE, ResourceType.PERMISSION))],
)
async def create_permission(
    payload: PermissionCreate,
    session: SessionDep,
) -> PermissionRead:
    service = PermissionService(session)
    try:
        permission = await service.create(payload)
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
    dependencies=[Depends(require_permission(Action.READ, ResourceType.PERMISSION))],
)
async def get_permission(permission_id: uuid.UUID, session: SessionDep) -> PermissionRead:
    service = PermissionService(session)
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
    dependencies=[Depends(require_permission(Action.DELETE, ResourceType.PERMISSION))],
)
async def delete_permission(
    permission_id: uuid.UUID,
    session: SessionDep,
) -> None:
    service = PermissionService(session)
    try:
        await service.delete(permission_id)
    except PermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission not found: {exc}",
        ) from exc
    await session.commit()
