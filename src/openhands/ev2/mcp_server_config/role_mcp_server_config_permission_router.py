"""HTTP routes for the role-MCP-server-config permission grant feature.

Uniform REST surface (AGENTS.md §3): the collection is
``/role-mcp-server-config-permissions`` with cursor pagination; create is
``POST``, update is ``PATCH`` (the link is mutable — toggle the
read/update/delete flags), retrieve is ``GET``, remove is ``DELETE``, plus
batch read/write.

The link table is a governed resource of its own: endpoints are authorized
through ``mcp_server_config_grant_permission`` (SEARCH for list/count, READ
for get/batch, CREATE/UPDATE/DELETE for grant changes). Managing a role's
MCP-config grants is deliberately not implied by ``role_permission`` update —
a principal who may edit a role's metadata must not be able to grant that
role access to arbitrary MCP server configs (that would be privilege
escalation / credential exfiltration). Every endpoint passes the effective
filter to the service, which scopes the SQL (AGENTS.md §9).
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
from openhands.ev2.mcp_server_config.mcp_server_config_models import (
    RoleMCPServerConfigPermission,
)
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_schemas import (
    RoleMCPServerConfigPermissionBatchWriteRequest,
    RoleMCPServerConfigPermissionCreate,
    RoleMCPServerConfigPermissionRead,
    RoleMCPServerConfigPermissionSearchFilter,
    RoleMCPServerConfigPermissionSearchResult,
    RoleMCPServerConfigPermissionUpdate,
)
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_service import (
    BatchPermissionDeniedError,
    RoleMCPServerConfigPermissionConflictError,
    RoleMCPServerConfigPermissionNotFoundError,
    RoleMCPServerConfigPermissionOrphanError,
    RoleMCPServerConfigPermissionScopeError,
    RoleMCPServerConfigPermissionService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(
    prefix="/role-mcp-server-config-permissions",
    tags=["role-mcp-server-config-permissions"],
)


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _to_read(link: Any) -> RoleMCPServerConfigPermissionRead:
    return RoleMCPServerConfigPermissionRead.model_validate(link)


def _scope_error(exc: RoleMCPServerConfigPermissionScopeError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Grant falls outside your create scope: {exc}",
    )


@router.get("", response_model=RoleMCPServerConfigPermissionSearchResult)
async def search_role_mcp_server_config_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.SEARCH)),
    ],
    search_filter: RoleMCPServerConfigPermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleMCPServerConfigPermissionSearchResult:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleMCPServerConfigPermissionSearchResult(
        items=[_to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_role_mcp_server_config_permissions(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.SEARCH)),
    ],
    search_filter: RoleMCPServerConfigPermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "",
    response_model=RoleMCPServerConfigPermissionRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_role_mcp_server_config_permission(
    payload: RoleMCPServerConfigPermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.CREATE)),
    ],
) -> RoleMCPServerConfigPermissionRead:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    try:
        link = await service.create(
            role_id=payload.role_id,
            mcp_server_config_id=payload.mcp_server_config_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except RoleMCPServerConfigPermissionScopeError as exc:
        raise _scope_error(exc) from exc
    except RoleMCPServerConfigPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleMCPServerConfigPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or MCP server config not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.get(
    "/batch",
    response_model=BatchReadResult[RoleMCPServerConfigPermissionRead],
)
async def get_role_mcp_server_config_permissions_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.READ)),
    ],
    # Declared before `/{role_mcp_server_config_permission_id}` so the static
    # `/batch` path matches ahead of the UUID path param. Default to an empty
    # list so an omitted `ids` param is valid (returns an empty result).
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleMCPServerConfigPermissionRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[_to_read(link) if link is not None else None for link in links],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[RoleMCPServerConfigPermissionRead],
)
async def write_role_mcp_server_config_permissions_batch(
    payload: RoleMCPServerConfigPermissionBatchWriteRequest,
    session: SessionDep,
    # Per-action filters resolved without raising so a batch that does not use
    # an action does not 403 on it; the service denies per operation.
    create_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission] | None,
        Depends(depends_permissions_or_none(RoleMCPServerConfigPermission, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission] | None,
        Depends(depends_permissions_or_none(RoleMCPServerConfigPermission, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission] | None,
        Depends(depends_permissions_or_none(RoleMCPServerConfigPermission, Action.DELETE)),
    ],
) -> BatchWriteResult[RoleMCPServerConfigPermissionRead]:
    service = RoleMCPServerConfigPermissionService(session)
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
    except RoleMCPServerConfigPermissionScopeError as exc:
        raise _scope_error(exc) from exc
    except RoleMCPServerConfigPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleMCPServerConfigPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or MCP server config not found: {exc}",
        ) from exc
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[_to_read(link) if link is not None else None for link in results],
    )


@router.get(
    "/{role_mcp_server_config_permission_id}",
    response_model=RoleMCPServerConfigPermissionRead,
)
async def get_role_mcp_server_config_permission(
    role_mcp_server_config_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.READ)),
    ],
) -> RoleMCPServerConfigPermissionRead:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    try:
        link = await service.get(role_mcp_server_config_permission_id)
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    return _to_read(link)


@router.patch(
    "/{role_mcp_server_config_permission_id}",
    response_model=RoleMCPServerConfigPermissionRead,
)
async def update_role_mcp_server_config_permission(
    role_mcp_server_config_permission_id: uuid.UUID,
    payload: RoleMCPServerConfigPermissionUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.UPDATE)),
    ],
) -> RoleMCPServerConfigPermissionRead:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    try:
        link = await service.update(role_mcp_server_config_permission_id, payload)
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.delete("/{role_mcp_server_config_permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_mcp_server_config_permission(
    role_mcp_server_config_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[RoleMCPServerConfigPermission],
        Depends(depends_permissions(RoleMCPServerConfigPermission, Action.DELETE)),
    ],
) -> None:
    service = RoleMCPServerConfigPermissionService(session, perm_filter)
    try:
        await service.delete(role_mcp_server_config_permission_id)
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
