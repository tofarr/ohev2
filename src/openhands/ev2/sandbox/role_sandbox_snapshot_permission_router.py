"""HTTP routes for role-sandbox-snapshot-permission grants.

Uniform REST surface (AGENTS.md §3): the collection is
``/role-sandbox-snapshot-permissions`` with cursor pagination; create is
``POST``, update is ``PATCH``, retrieve is ``GET``, remove is ``DELETE``,
plus batch read/write. Mirrors ``role_secret_permission_router``.
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
from openhands.ev2.sandbox.role_sandbox_snapshot_permission_schemas import (
    RoleSandboxSnapshotPermissionBatchWriteRequest,
    RoleSandboxSnapshotPermissionCreate,
    RoleSandboxSnapshotPermissionRead,
    RoleSandboxSnapshotPermissionSearchFilter,
    RoleSandboxSnapshotPermissionSearchResult,
    RoleSandboxSnapshotPermissionUpdate,
)
from openhands.ev2.sandbox.role_sandbox_snapshot_permission_service import (
    BatchPermissionDeniedError,
    RoleSandboxSnapshotPermissionConflictError,
    RoleSandboxSnapshotPermissionNotFoundError,
    RoleSandboxSnapshotPermissionOrphanError,
    RoleSandboxSnapshotPermissionScopeError,
    RoleSandboxSnapshotPermissionService,
)
from openhands.ev2.sandbox.sandbox_models import RoleSandboxSnapshotPermission
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import AllSearchFilter, SearchFilter

router = APIRouter(
    prefix="/role-sandbox-snapshot-permissions",
    tags=["role-sandbox-snapshot-permissions"],
)


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _map_exception_to_status(exc: Exception) -> HTTPException:
    if isinstance(exc, RoleSandboxSnapshotPermissionConflictError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, RoleSandboxSnapshotPermissionOrphanError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if isinstance(exc, RoleSandboxSnapshotPermissionScopeError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, RoleSandboxSnapshotPermissionNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, BatchPermissionDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("", response_model=RoleSandboxSnapshotPermissionRead, status_code=201)
async def create_role_sandbox_snapshot_permission(
    payload: RoleSandboxSnapshotPermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission],
        Depends(depends_permissions(RoleSandboxSnapshotPermission, Action.CREATE)),
    ],
) -> RoleSandboxSnapshotPermissionRead:
    service = RoleSandboxSnapshotPermissionService(session, perm_filter)
    try:
        link = await service.create(
            role_id=payload.role_id,
            sandbox_snapshot_id=payload.sandbox_snapshot_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return RoleSandboxSnapshotPermissionRead.model_validate(link)


@router.get("", response_model=RoleSandboxSnapshotPermissionSearchResult)
async def list_role_sandbox_snapshot_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.SEARCH)),
    ],
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor for pagination.")] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Page size.")] = 50,
    role_id: Annotated[uuid.UUID | None, Query()] = None,
    sandbox_snapshot_id: Annotated[uuid.UUID | None, Query()] = None,
    read_enabled: Annotated[bool | None, Query()] = None,
    update_enabled: Annotated[bool | None, Query()] = None,
    delete_enabled: Annotated[bool | None, Query()] = None,
) -> RoleSandboxSnapshotPermissionSearchResult:
    search_filter = RoleSandboxSnapshotPermissionSearchFilter(
        role_id__eq=role_id,
        sandbox_snapshot_id__eq=sandbox_snapshot_id,
        read_enabled__eq=read_enabled,
        update_enabled__eq=update_enabled,
        delete_enabled__eq=delete_enabled,
    )
    service = RoleSandboxSnapshotPermissionService(session, perm_filter or AllSearchFilter[Any]())
    links, next_cursor = await service.search_role_sandbox_snapshot_permissions(
        cursor=_cursor(cursor) if cursor else None,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleSandboxSnapshotPermissionSearchResult(
        items=[RoleSandboxSnapshotPermissionRead.model_validate(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_role_sandbox_snapshot_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.SEARCH)),
    ],
    role_id: Annotated[uuid.UUID | None, Query()] = None,
    sandbox_snapshot_id: Annotated[uuid.UUID | None, Query()] = None,
    read_enabled: Annotated[bool | None, Query()] = None,
    update_enabled: Annotated[bool | None, Query()] = None,
    delete_enabled: Annotated[bool | None, Query()] = None,
) -> CountResult:
    search_filter = RoleSandboxSnapshotPermissionSearchFilter(
        role_id__eq=role_id,
        sandbox_snapshot_id__eq=sandbox_snapshot_id,
        read_enabled__eq=read_enabled,
        update_enabled__eq=update_enabled,
        delete_enabled__eq=delete_enabled,
    )
    service = RoleSandboxSnapshotPermissionService(session, perm_filter or AllSearchFilter[Any]())
    return CountResult(count=await service.count(search_filter=search_filter))


@router.get("/batch", response_model=BatchReadResult[RoleSandboxSnapshotPermissionRead])
async def batch_read_role_sandbox_snapshot_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleSandboxSnapshotPermissionRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A batch read accepts at most 100 ids.",
        )
    service = RoleSandboxSnapshotPermissionService(session, perm_filter or AllSearchFilter[Any]())
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[
            RoleSandboxSnapshotPermissionRead.model_validate(link) if link else None
            for link in links
        ],
    )


@router.post("/batch", response_model=BatchWriteResult[RoleSandboxSnapshotPermissionRead])
async def batch_write_role_sandbox_snapshot_permissions(
    payload: RoleSandboxSnapshotPermissionBatchWriteRequest,
    session: SessionDep,
    create_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.DELETE)),
    ],
) -> BatchWriteResult[RoleSandboxSnapshotPermissionRead]:
    service = RoleSandboxSnapshotPermissionService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return BatchWriteResult(
        items=[
            RoleSandboxSnapshotPermissionRead.model_validate(link) if link else None
            for link in results
        ],
    )


@router.get(
    "/{role_sandbox_snapshot_permission_id}",
    response_model=RoleSandboxSnapshotPermissionRead,
)
async def get_role_sandbox_snapshot_permission(
    role_sandbox_snapshot_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission] | None,
        Depends(depends_permissions_or_none(RoleSandboxSnapshotPermission, Action.READ)),
    ],
) -> RoleSandboxSnapshotPermissionRead:
    service = RoleSandboxSnapshotPermissionService(session, perm_filter or AllSearchFilter[Any]())
    try:
        link = await service.get(role_sandbox_snapshot_permission_id)
    except RoleSandboxSnapshotPermissionNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return RoleSandboxSnapshotPermissionRead.model_validate(link)


@router.patch(
    "/{role_sandbox_snapshot_permission_id}",
    response_model=RoleSandboxSnapshotPermissionRead,
)
async def update_role_sandbox_snapshot_permission(
    role_sandbox_snapshot_permission_id: uuid.UUID,
    payload: RoleSandboxSnapshotPermissionUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission],
        Depends(depends_permissions(RoleSandboxSnapshotPermission, Action.UPDATE)),
    ],
) -> RoleSandboxSnapshotPermissionRead:
    service = RoleSandboxSnapshotPermissionService(session, perm_filter)
    try:
        link = await service.update(role_sandbox_snapshot_permission_id, payload)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return RoleSandboxSnapshotPermissionRead.model_validate(link)


@router.delete("/{role_sandbox_snapshot_permission_id}", status_code=204)
async def delete_role_sandbox_snapshot_permission(
    role_sandbox_snapshot_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSandboxSnapshotPermission],
        Depends(depends_permissions(RoleSandboxSnapshotPermission, Action.DELETE)),
    ],
) -> None:
    service = RoleSandboxSnapshotPermissionService(session, perm_filter)
    try:
        await service.delete(role_sandbox_snapshot_permission_id)
    except RoleSandboxSnapshotPermissionNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
