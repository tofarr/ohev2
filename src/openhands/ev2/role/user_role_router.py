"""HTTP routes for the user-role assignment feature.

Uniform REST surface (AGENTS.md §3). The collection is ``/user-roles`` with
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
from openhands.ev2.role.role_models import Role
from openhands.ev2.role.user_role_schemas import (
    UserRoleBatchWriteRequest,
    UserRoleCreate,
    UserRoleRead,
    UserRoleSearchFilter,
    UserRoleSearchResult,
)
from openhands.ev2.role.user_role_service import (
    UserRoleConflictError,
    UserRoleNotFoundError,
    UserRoleOrphanError,
    UserRoleService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/user-roles", tags=["user-roles"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


async def _to_read(link: Any) -> UserRoleRead:
    return UserRoleRead(
        id=link.id,
        role_id=link.role_id,
        user_id=link.user_id,
        created_at=link.created_at,
    )


@router.get("", response_model=UserRoleSearchResult)
async def search_user_roles(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: UserRoleSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserRoleSearchResult:
    _ = perm_filter  # assignments are global; the filter only gates access.
    service = UserRoleService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_user_roles(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return UserRoleSearchResult(
        items=[await _to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_user_roles(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: UserRoleSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = UserRoleService(session)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=UserRoleRead, status_code=status.HTTP_201_CREATED)
async def create_user_role(
    payload: UserRoleCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> UserRoleRead:
    _ = perm_filter
    service = UserRoleService(session)
    try:
        link = await service.create(payload.role_id, payload.user_id)
    except UserRoleConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Assignment already exists: {exc}",
        ) from exc
    except UserRoleOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or user not found: {exc}",
        ) from exc
    await session.commit()
    return await _to_read(link)


@router.get(
    "/batch",
    response_model=BatchReadResult[UserRoleRead],
)
async def get_user_roles_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    # Declared before `/{user_role_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[UserRoleRead]:
    _ = perm_filter
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = UserRoleService(session)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[await _to_read(link) if link is not None else None for link in links],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[UserRoleRead],
)
async def write_user_roles_batch(
    payload: UserRoleBatchWriteRequest,
    session: SessionDep,
    # Managing assignments requires UPDATE on the role resource, mirroring the
    # single-item create/delete endpoints. Declared before `/{user_role_id}` so
    # the static `/batch` path matches ahead of the UUID path param.
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> BatchWriteResult[UserRoleRead]:
    _ = perm_filter
    service = UserRoleService(session)
    try:
        results = await service.apply_batch(payload.operations)
    except UserRoleConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Assignment already exists: {exc}",
        ) from exc
    except UserRoleOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or user not found: {exc}",
        ) from exc
    except UserRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[await _to_read(link) if link is not None else None for link in results],
    )


@router.get("/{user_role_id}", response_model=UserRoleRead)
async def get_user_role(
    user_role_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
) -> UserRoleRead:
    _ = perm_filter
    service = UserRoleService(session)
    try:
        link = await service.get(user_role_id)
    except UserRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    return await _to_read(link)


@router.delete("/{user_role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_role(
    user_role_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = UserRoleService(session)
    try:
        await service.delete(user_role_id)
    except UserRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    await session.commit()
