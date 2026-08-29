"""HTTP routes for the role feature.

Follows the uniform REST surface (AGENTS.md §3): GET /roles (paginated),
POST /roles, GET/PATCH/DELETE /roles/{id}. Handlers validate, call the
service, and serialize — no business logic here. Every endpoint is guarded by
the centralized permission checker (AGENTS.md §9); the returned
:class:`SearchFilter` is passed into the service constructor so search/update/
delete SQL and create payloads are scoped to the principal.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.role.role_models import Role
from openhands.ev2.role.role_schemas import (
    RoleCreate,
    RoleRead,
    RoleSearchFilter,
    RoleSearchResult,
    RoleUpdate,
)
from openhands.ev2.role.role_service import (
    RoleNameConflictError,
    RoleNotFoundError,
    RolePermissionScopeError,
    RoleService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/roles", tags=["roles"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=RoleSearchResult)
async def search_roles(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.SEARCH))],
    search_filter: RoleSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleSearchResult:
    service = RoleService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    roles, next_cursor = await service.search_roles(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleSearchResult(
        items=[RoleRead.model_validate(r) for r in roles],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_roles(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.SEARCH))],
    search_filter: RoleSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = RoleService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.CREATE))],
) -> RoleRead:
    service = RoleService(session, perm_filter)
    try:
        role = await service.create(payload)
    except RolePermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role falls outside your create scope: {exc}",
        ) from exc
    except RoleNameConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role with name already exists: {exc}",
        ) from exc
    await session.commit()
    return RoleRead.model_validate(role)


@router.get(
    "/batch",
    response_model=BatchReadResult[RoleRead],
)
async def get_roles_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.READ))],
    # Declared before `/{role_id}` so the static `/batch` path matches ahead of
    # the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleService(session, perm_filter)
    roles = await service.get_many(ids)
    return BatchReadResult(
        items=[RoleRead.model_validate(r) if r is not None else None for r in roles],
    )


@router.get("/{role_id}", response_model=RoleRead)
async def get_role(
    role_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.READ))],
) -> RoleRead:
    service = RoleService(session, perm_filter)
    try:
        role = await service.get(role_id)
    except RoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role not found: {exc}",
        ) from exc
    return RoleRead.model_validate(role)


@router.patch("/{role_id}", response_model=RoleRead)
async def update_role(
    role_id: uuid.UUID,
    payload: RoleUpdate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleRead:
    service = RoleService(session, perm_filter)
    try:
        role = await service.update(role_id, payload)
    except RoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role not found: {exc}",
        ) from exc
    except RoleNameConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role with name already exists: {exc}",
        ) from exc
    await session.commit()
    return RoleRead.model_validate(role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Role], Depends(depends_permissions(Role, Action.DELETE))],
) -> None:
    service = RoleService(session, perm_filter)
    try:
        await service.delete(role_id)
    except RoleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role not found: {exc}",
        ) from exc
    await session.commit()
