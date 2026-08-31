"""HTTP routes for the role-secret-permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/role-secret-permissions`` with
cursor pagination; create is ``POST``, update is ``PATCH`` (the link is
mutable — toggle the read/update/delete flags), retrieve is ``GET``, remove
is ``DELETE``, plus batch read/write.

Authorization models the link as a sub-resource of ``role`` (mirroring
``/user-roles``): managing a role's secret grants requires the ``UPDATE``
action on the ``role`` resource, while listing and retrieving grants requires
``READ`` on the ``role`` resource. Every endpoint is guarded by the
centralized permission checker (AGENTS.md §9).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.role.role_models import Role
from openhands.ev2.secret.role_secret_permission_schemas import (
    RoleSecretPermissionBatchWriteRequest,
    RoleSecretPermissionCreate,
    RoleSecretPermissionRead,
    RoleSecretPermissionSearchFilter,
    RoleSecretPermissionSearchResult,
    RoleSecretPermissionUpdate,
)
from openhands.ev2.secret.role_secret_permission_service import (
    RoleSecretPermissionConflictError,
    RoleSecretPermissionNotFoundError,
    RoleSecretPermissionOrphanError,
    RoleSecretPermissionService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/role-secret-permissions", tags=["role-secret-permissions"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _to_read(link: Any) -> RoleSecretPermissionRead:
    return RoleSecretPermissionRead.model_validate(link)


@router.get("", response_model=RoleSecretPermissionSearchResult)
async def search_role_secret_permissions(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleSecretPermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleSecretPermissionSearchResult:
    _ = perm_filter  # grants are global; the filter only gates access.
    service = RoleSecretPermissionService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_role_secret_permissions(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleSecretPermissionSearchResult(
        items=[_to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_role_secret_permissions(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleSecretPermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=RoleSecretPermissionRead, status_code=status.HTTP_201_CREATED)
async def create_role_secret_permission(
    payload: RoleSecretPermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleSecretPermissionRead:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    try:
        link = await service.create(
            role_id=payload.role_id,
            secret_id=payload.secret_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except RoleSecretPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleSecretPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or secret not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.get(
    "/batch",
    response_model=BatchReadResult[RoleSecretPermissionRead],
)
async def get_role_secret_permissions_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    # Declared before `/{role_secret_permission_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleSecretPermissionRead]:
    _ = perm_filter
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleSecretPermissionService(session)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[_to_read(link) if link is not None else None for link in links],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[RoleSecretPermissionRead],
)
async def write_role_secret_permissions_batch(
    payload: RoleSecretPermissionBatchWriteRequest,
    session: SessionDep,
    # Managing grants requires UPDATE on the role resource, mirroring the
    # single-item create/update/delete endpoints.
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> BatchWriteResult[RoleSecretPermissionRead]:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    try:
        results = await service.apply_batch(payload.operations)
    except RoleSecretPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleSecretPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or secret not found: {exc}",
        ) from exc
    except RoleSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[_to_read(link) if link is not None else None for link in results],
    )


@router.get("/{role_secret_permission_id}", response_model=RoleSecretPermissionRead)
async def get_role_secret_permission(
    role_secret_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
) -> RoleSecretPermissionRead:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    try:
        link = await service.get(role_secret_permission_id)
    except RoleSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    return _to_read(link)


@router.patch("/{role_secret_permission_id}", response_model=RoleSecretPermissionRead)
async def update_role_secret_permission(
    role_secret_permission_id: uuid.UUID,
    payload: RoleSecretPermissionUpdate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleSecretPermissionRead:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    try:
        link = await service.update(role_secret_permission_id, payload)
    except RoleSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.delete("/{role_secret_permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_secret_permission(
    role_secret_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = RoleSecretPermissionService(session)
    try:
        await service.delete(role_secret_permission_id)
    except RoleSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
