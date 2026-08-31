"""HTTP routes for role-MCP-server-config permission grants."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_schemas import (
    RoleMCPServerConfigPermissionBatchWriteRequest,
    RoleMCPServerConfigPermissionCreate,
    RoleMCPServerConfigPermissionRead,
    RoleMCPServerConfigPermissionSearchFilter,
    RoleMCPServerConfigPermissionSearchResult,
    RoleMCPServerConfigPermissionUpdate,
)
from openhands.ev2.mcp_server_config.role_mcp_server_config_permission_service import (
    RoleMCPServerConfigPermissionConflictError,
    RoleMCPServerConfigPermissionNotFoundError,
    RoleMCPServerConfigPermissionOrphanError,
    RoleMCPServerConfigPermissionService,
)
from openhands.ev2.role.role_models import Role
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


@router.get("", response_model=RoleMCPServerConfigPermissionSearchResult)
async def search_role_mcp_server_config_permissions(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleMCPServerConfigPermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleMCPServerConfigPermissionSearchResult:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
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
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleMCPServerConfigPermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
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
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleMCPServerConfigPermissionRead:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
    try:
        link = await service.create(
            role_id=payload.role_id,
            mcp_server_config_id=payload.mcp_server_config_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
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


@router.get("/batch", response_model=BatchReadResult[RoleMCPServerConfigPermissionRead])
async def get_role_mcp_server_config_permissions_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleMCPServerConfigPermissionRead]:
    _ = perm_filter
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleMCPServerConfigPermissionService(session)
    links = await service.get_many(ids)
    return BatchReadResult(items=[_to_read(link) if link is not None else None for link in links])


@router.post("/batch", response_model=BatchWriteResult[RoleMCPServerConfigPermissionRead])
async def write_role_mcp_server_config_permissions_batch(
    payload: RoleMCPServerConfigPermissionBatchWriteRequest,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> BatchWriteResult[RoleMCPServerConfigPermissionRead]:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
    try:
        results = await service.apply_batch(payload.operations)
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
        items=[_to_read(link) if link is not None else None for link in results]
    )


@router.get(
    "/{role_mcp_server_config_permission_id}",
    response_model=RoleMCPServerConfigPermissionRead,
)
async def get_role_mcp_server_config_permission(
    role_mcp_server_config_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
) -> RoleMCPServerConfigPermissionRead:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
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
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleMCPServerConfigPermissionRead:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
    try:
        link = await service.update(role_mcp_server_config_permission_id, payload)
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.delete(
    "/{role_mcp_server_config_permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_role_mcp_server_config_permission(
    role_mcp_server_config_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = RoleMCPServerConfigPermissionService(session)
    try:
        await service.delete(role_mcp_server_config_permission_id)
    except RoleMCPServerConfigPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
