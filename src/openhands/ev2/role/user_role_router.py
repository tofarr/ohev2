"""HTTP routes for the user-role assignment feature.

Uniform REST surface (AGENTS.md §3). The collection is ``/user-roles`` with
cursor pagination; create is ``POST``, retrieve is ``GET``, remove is
``DELETE``. Assignments are immutable; there is no update.

The link table is a governed resource of its own: endpoints are authorized
through ``user_role_permission`` (SEARCH for list/count, READ for get/batch,
CREATE/DELETE for membership changes). Managing membership is deliberately not
implied by ``role_permission`` update — a principal who may edit a role's
metadata must not be able to decide who holds it (that would be privilege
escalation). Every endpoint passes the effective filter to the service, which
scopes the SQL (AGENTS.md §9).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.role.role_models import UserRole as UserRoleModel
from openhands.ev2.role.user_role_schemas import (
    UserRoleBatchWriteRequest,
    UserRoleCreate,
    UserRoleRead,
    UserRoleSearchFilter,
    UserRoleSearchResult,
)
from openhands.ev2.role.user_role_service import (
    BatchPermissionDeniedError,
    UserRoleConflictError,
    UserRoleNotFoundError,
    UserRoleOrphanError,
    UserRolePermissionScopeError,
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
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.SEARCH))
    ],
    search_filter: UserRoleSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserRoleSearchResult:
    service = UserRoleService(session, perm_filter)
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
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.SEARCH))
    ],
    search_filter: UserRoleSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = UserRoleService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=UserRoleRead, status_code=status.HTTP_201_CREATED)
async def create_user_role(
    payload: UserRoleCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.CREATE))
    ],
) -> UserRoleRead:
    service = UserRoleService(session, perm_filter)
    try:
        link = await service.create(payload.role_id, payload.user_id)
    except UserRolePermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Assignment falls outside your create scope: {exc}",
        ) from exc
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
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.READ))
    ],
    # Declared before `/{user_role_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[UserRoleRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = UserRoleService(session, perm_filter)
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
    # Per-action filters resolved without raising so a batch that uses only
    # one action does not 403 on the other; the service denies per operation.
    # Declared before `/{user_role_id}` so the static `/batch` path matches
    # ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[UserRoleModel] | None,
        Depends(depends_permissions_or_none(UserRoleModel, Action.CREATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[UserRoleModel] | None,
        Depends(depends_permissions_or_none(UserRoleModel, Action.DELETE)),
    ],
) -> BatchWriteResult[UserRoleRead]:
    service = UserRoleService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except UserRolePermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Assignment falls outside your create scope: {exc}",
        ) from exc
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
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.READ))
    ],
) -> UserRoleRead:
    service = UserRoleService(session, perm_filter)
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
    perm_filter: Annotated[
        SearchFilter[UserRoleModel], Depends(depends_permissions(UserRoleModel, Action.DELETE))
    ],
) -> None:
    service = UserRoleService(session, perm_filter)
    try:
        await service.delete(user_role_id)
    except UserRoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assignment not found: {exc}",
        ) from exc
    await session.commit()
