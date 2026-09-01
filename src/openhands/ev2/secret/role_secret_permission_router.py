"""HTTP routes for the role-secret-permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/role-secret-permissions`` with
cursor pagination; create is ``POST``, update is ``PATCH`` (the link is
mutable — toggle the read/update/delete flags), retrieve is ``GET``, remove
is ``DELETE``, plus batch read/write.

The link table is a governed resource of its own: endpoints are authorized
through ``secret_grant_permission`` (SEARCH for list/count, READ for
get/batch, CREATE/UPDATE/DELETE for grant changes). Managing a role's secret
grants is deliberately not implied by ``role_permission`` update — a
principal who may edit a role's metadata must not be able to grant that role
access to arbitrary secrets (that would be privilege escalation / secret
exfiltration). Every endpoint passes the effective filter to the service,
which scopes the SQL (AGENTS.md §9).
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
from openhands.ev2.secret.role_secret_permission_schemas import (
    RoleSecretPermissionBatchWriteRequest,
    RoleSecretPermissionCreate,
    RoleSecretPermissionRead,
    RoleSecretPermissionSearchFilter,
    RoleSecretPermissionSearchResult,
    RoleSecretPermissionUpdate,
)
from openhands.ev2.secret.role_secret_permission_service import (
    BatchPermissionDeniedError,
    RoleSecretPermissionConflictError,
    RoleSecretPermissionNotFoundError,
    RoleSecretPermissionOrphanError,
    RoleSecretPermissionScopeError,
    RoleSecretPermissionService,
)
from openhands.ev2.secret.secret_models import RoleSecretPermission
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


def _scope_error(exc: RoleSecretPermissionScopeError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Grant falls outside your create scope: {exc}",
    )


@router.get("", response_model=RoleSecretPermissionSearchResult)
async def search_role_secret_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.SEARCH)),
    ],
    search_filter: RoleSecretPermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleSecretPermissionSearchResult:
    service = RoleSecretPermissionService(session, perm_filter)
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
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.SEARCH)),
    ],
    search_filter: RoleSecretPermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = RoleSecretPermissionService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=RoleSecretPermissionRead, status_code=status.HTTP_201_CREATED)
async def create_role_secret_permission(
    payload: RoleSecretPermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.CREATE)),
    ],
) -> RoleSecretPermissionRead:
    service = RoleSecretPermissionService(session, perm_filter)
    try:
        link = await service.create(
            role_id=payload.role_id,
            secret_id=payload.secret_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except RoleSecretPermissionScopeError as exc:
        raise _scope_error(exc) from exc
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
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.READ)),
    ],
    # Declared before `/{role_secret_permission_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleSecretPermissionRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleSecretPermissionService(session, perm_filter)
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
    # Per-action filters resolved without raising so a batch that does not use
    # an action does not 403 on it; the service denies per operation.
    create_filter: Annotated[
        SearchFilter[RoleSecretPermission] | None,
        Depends(depends_permissions_or_none(RoleSecretPermission, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[RoleSecretPermission] | None,
        Depends(depends_permissions_or_none(RoleSecretPermission, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[RoleSecretPermission] | None,
        Depends(depends_permissions_or_none(RoleSecretPermission, Action.DELETE)),
    ],
) -> BatchWriteResult[RoleSecretPermissionRead]:
    service = RoleSecretPermissionService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except RoleSecretPermissionScopeError as exc:
        raise _scope_error(exc) from exc
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
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.READ)),
    ],
) -> RoleSecretPermissionRead:
    service = RoleSecretPermissionService(session, perm_filter)
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
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.UPDATE)),
    ],
) -> RoleSecretPermissionRead:
    service = RoleSecretPermissionService(session, perm_filter)
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
    perm_filter: Annotated[
        SearchFilter[RoleSecretPermission],
        Depends(depends_permissions(RoleSecretPermission, Action.DELETE)),
    ],
) -> None:
    service = RoleSecretPermissionService(session, perm_filter)
    try:
        await service.delete(role_secret_permission_id)
    except RoleSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
