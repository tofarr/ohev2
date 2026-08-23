"""HTTP routes for the permission feature.

Uniform REST surface (AGENTS.md §3). Supports filtering the collection by user
via `?user_id=…` — a query param on the collection, never a bespoke route.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.db import get_session
from ohev.permission.schemas import (
    PermissionCreate,
    PermissionList,
    PermissionRead,
    PermissionUpdate,
)
from ohev.permission.services import (
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


SessionDep = Annotated[AsyncSession, Depends(get_session)]


@router.get("", response_model=PermissionList)
async def list_permissions(
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> PermissionList:
    service = PermissionService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    permissions, next_cursor = await service.list_permissions(
        user_id=user_id, cursor=cursor_uuid, limit=limit
    )
    return PermissionList(
        items=[PermissionRead.model_validate(p) for p in permissions],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post("", response_model=PermissionRead, status_code=status.HTTP_201_CREATED)
async def create_permission(payload: PermissionCreate, session: SessionDep) -> PermissionRead:
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


@router.get("/{permission_id}", response_model=PermissionRead)
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


@router.patch("/{permission_id}", response_model=PermissionRead)
async def update_permission(
    permission_id: uuid.UUID,
    payload: PermissionUpdate,
    session: SessionDep,
) -> PermissionRead:
    service = PermissionService(session)
    try:
        permission = await service.update(permission_id, payload)
    except PermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission not found: {exc}",
        ) from exc
    except PermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission already exists: {exc}",
        ) from exc
    await session.commit()
    return PermissionRead.model_validate(permission)


@router.delete("/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(permission_id: uuid.UUID, session: SessionDep) -> None:
    service = PermissionService(session)
    try:
        await service.delete(permission_id)
    except PermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission not found: {exc}",
        ) from exc
    await session.commit()
