"""HTTP routes for the role-user assignment feature.

Uniform REST surface (AGENTS.md §3). The collection is ``/role-users`` with
cursor pagination; create is ``POST``, retrieve is ``GET``, remove is
``DELETE``. Assignments are immutable; there is no update.

Authorization models the link as a sub-resource of ``role``: managing role
membership requires the ``UPDATE`` action on the ``role`` resource (a principal
who can update a role can assign/unassign users to it), while listing and
retrieving assignments requires ``READ`` on the ``role`` resource. Every
endpoint is guarded by the centralized permission checker (AGENTS.md §9).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.role.role_user_schemas import (
    RoleUserCreate,
    RoleUserRead,
    RoleUserSearchFilter,
    RoleUserSearchResult,
)
from openhands.ev2.role.role_user_service import (
    RoleUserConflictError,
    RoleUserNotFoundError,
    RoleUserOrphanError,
    RoleUserService,
)
from openhands.ev2.security.security_models import Action, Role
from openhands.ev2.util.schemas import CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/role-users", tags=["role-users"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


async def _to_read(link: Any) -> RoleUserRead:
    return RoleUserRead(
        id=link.id,
        role_id=link.role_id,
        user_id=link.user_id,
        created_at=link.created_at,
    )


@router.get("", response_model=RoleUserSearchResult)
async def search_role_users(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleUserSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleUserSearchResult:
    _ = perm_filter  # assignments are global; the filter only gates access.
    service = RoleUserService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_role_users(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleUserSearchResult(
        items=[await _to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_role_users(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleUserSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = RoleUserService(session)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=RoleUserRead, status_code=status.HTTP_201_CREATED)
async def create_role_user(
    payload: RoleUserCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleUserRead:
    _ = perm_filter
    service = RoleUserService(session)
    try:
        link = await service.create(payload.role_id, payload.user_id)
    except RoleUserConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Assignment already exists: {exc}",
        ) from exc
    except RoleUserOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or user not found: {exc}",
        ) from exc
    await session.commit()
    return await _to_read(link)


@router.get("/{role_user_id}", response_model=RoleUserRead)
async def get_role_user(
    role_user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
) -> RoleUserRead:
    _ = perm_filter
    service = RoleUserService(session)
    try:
        link = await service.get(role_user_id)
    except RoleUserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    return await _to_read(link)


@router.delete("/{role_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_user(
    role_user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = RoleUserService(session)
    try:
        await service.delete(role_user_id)
    except RoleUserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    await session.commit()
