"""HTTP routes for MCP server configuration resources."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.mcp_server_config.mcp_server_config_models import MCPServerConfig
from openhands.ev2.mcp_server_config.mcp_server_config_schemas import (
    MCPServerConfigBatchWriteRequest,
    MCPServerConfigCreate,
    MCPServerConfigRead,
    MCPServerConfigSearchFilter,
    MCPServerConfigSearchResult,
    MCPServerConfigUpdate,
)
from openhands.ev2.mcp_server_config.mcp_server_config_service import (
    BatchPermissionDeniedError,
    MCPServerConfigNotFoundError,
    MCPServerConfigPermissionScopeError,
    MCPServerConfigService,
    MCPServerConfigValidationError,
)
from openhands.ev2.mcp_server_config.mcp_usage_models import McpAggregatedUsage
from openhands.ev2.mcp_server_config.mcp_usage_schemas import (
    McpAggregatedUsageRead,
    McpAggregatedUsageSearchFilter,
    McpAggregatedUsageSearchResult,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/mcp-server-configs", tags=["mcp-server-configs"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _validation_error(exc: MCPServerConfigValidationError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=f"Invalid MCP server config: {exc}",
    )


@router.get("", response_model=MCPServerConfigSearchResult)
async def search_mcp_server_configs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.SEARCH)),
    ],
    search_filter: MCPServerConfigSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> MCPServerConfigSearchResult:
    service = MCPServerConfigService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return MCPServerConfigSearchResult(
        items=[service.to_read(row) for row in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_mcp_server_configs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.SEARCH)),
    ],
    search_filter: MCPServerConfigSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = MCPServerConfigService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=MCPServerConfigRead, status_code=status.HTTP_201_CREATED)
async def create_mcp_server_config(
    payload: MCPServerConfigCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.CREATE)),
    ],
) -> MCPServerConfigRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = MCPServerConfigService(session, perm_filter)
    try:
        config = await service.create(payload, user_id=user_id)
    except MCPServerConfigPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"MCP server config falls outside your create scope: {exc}",
        ) from exc
    except MCPServerConfigValidationError as exc:
        raise _validation_error(exc) from exc
    await session.commit()
    return service.to_read(config)


@router.get("/batch", response_model=BatchReadResult[MCPServerConfigRead])
async def get_mcp_server_configs_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[MCPServerConfigRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = MCPServerConfigService(session, perm_filter)
    configs = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(config) if config is not None else None for config in configs]
    )


@router.post("/batch", response_model=BatchWriteResult[MCPServerConfigRead])
async def write_mcp_server_configs_batch(
    payload: MCPServerConfigBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    create_filter: Annotated[
        SearchFilter[MCPServerConfig] | None,
        Depends(depends_permissions_or_none(MCPServerConfig, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[MCPServerConfig] | None,
        Depends(depends_permissions_or_none(MCPServerConfig, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[MCPServerConfig] | None,
        Depends(depends_permissions_or_none(MCPServerConfig, Action.DELETE)),
    ],
) -> BatchWriteResult[MCPServerConfigRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = MCPServerConfigService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, user_id=user_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except MCPServerConfigPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"MCP server config falls outside your create scope: {exc}",
        ) from exc
    except MCPServerConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server config not found: {exc}",
        ) from exc
    except MCPServerConfigValidationError as exc:
        raise _validation_error(exc) from exc
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(config) if config is not None else None for config in results]
    )


# ---------------------------------------------------------------------- #
# MCP aggregated usage (read-only projection of mcp_usage)
#
# The raw ``mcp_usage`` table (daily-partitioned, append-only) is not exposed
# over REST. Usage queries go through the ``mcp_aggregated_usage`` projection
# — per-minute, per-user rollups exposed read-only here. Only SEARCH / READ /
# batch-read are wired — there is no create/update/delete (the projection is
# populated by the background aggregator), so per AGENTS.md §3 no batch write
# endpoint is required. These routes are declared before ``/{config_id}`` so
# the UUID path parameter does not shadow the ``aggregated-usage`` literal.
# ---------------------------------------------------------------------- #


@router.get(
    "/aggregated-usage",
    response_model=McpAggregatedUsageSearchResult,
)
async def search_mcp_aggregated_usage(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[McpAggregatedUsage],
        Depends(depends_permissions(McpAggregatedUsage, Action.SEARCH)),
    ],
    search_filter: McpAggregatedUsageSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> McpAggregatedUsageSearchResult:
    """List per-minute, per-user MCP usage rollups (paginated, scoped by permissions)."""
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    stmt = perm_filter.filter_sql(select(McpAggregatedUsage).order_by(McpAggregatedUsage.id))
    if search_filter is not None:
        stmt = search_filter.filter_sql(stmt)
    if cursor_uuid is not None:
        stmt = stmt.where(McpAggregatedUsage.id > cursor_uuid)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    next_cursor = rows[-1].id if len(rows) == limit else None
    return McpAggregatedUsageSearchResult(
        items=[McpAggregatedUsageRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/aggregated-usage/count", response_model=CountResult)
async def count_mcp_aggregated_usage(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[McpAggregatedUsage],
        Depends(depends_permissions(McpAggregatedUsage, Action.SEARCH)),
    ],
    search_filter: McpAggregatedUsageSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    """Count per-minute, per-user MCP usage rollups in the principal's scope."""
    stmt = perm_filter.filter_sql(select(func.count()).select_from(McpAggregatedUsage))
    if search_filter is not None:
        stmt = search_filter.filter_sql(stmt)
    result = await session.execute(stmt)
    return CountResult(count=int(result.scalar_one()))


@router.get(
    "/aggregated-usage/batch",
    response_model=BatchReadResult[McpAggregatedUsageRead],
)
async def get_mcp_aggregated_usage_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[McpAggregatedUsage],
        Depends(depends_permissions(McpAggregatedUsage, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[McpAggregatedUsageRead]:
    """Batch read MCP aggregated-usage rows by id (positional, null for missing)."""
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    if not ids:
        return BatchReadResult(items=[])
    stmt = perm_filter.filter_sql(select(McpAggregatedUsage).where(McpAggregatedUsage.id.in_(ids)))
    result = await session.execute(stmt)
    by_id: dict[uuid.UUID, McpAggregatedUsage] = {row.id: row for row in result.scalars().all()}
    return BatchReadResult(
        items=[
            McpAggregatedUsageRead.model_validate(by_id[i]) if i in by_id else None for i in ids
        ],
    )


@router.get(
    "/aggregated-usage/{row_id}",
    response_model=McpAggregatedUsageRead,
)
async def get_mcp_aggregated_usage(
    row_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[McpAggregatedUsage],
        Depends(depends_permissions(McpAggregatedUsage, Action.READ)),
    ],
) -> McpAggregatedUsageRead:
    """Retrieve one MCP aggregated-usage rollup by id."""
    stmt = perm_filter.filter_sql(select(McpAggregatedUsage).where(McpAggregatedUsage.id == row_id))
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP aggregated usage not found: {row_id}",
        )
    return McpAggregatedUsageRead.model_validate(row)


@router.get("/{config_id}", response_model=MCPServerConfigRead)
async def get_mcp_server_config(
    config_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.READ)),
    ],
) -> MCPServerConfigRead:
    service = MCPServerConfigService(session, perm_filter)
    try:
        config = await service.get(config_id)
    except MCPServerConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server config not found: {exc}",
        ) from exc
    return service.to_read(config)


@router.patch("/{config_id}", response_model=MCPServerConfigRead)
async def update_mcp_server_config(
    config_id: uuid.UUID,
    payload: MCPServerConfigUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.UPDATE)),
    ],
) -> MCPServerConfigRead:
    service = MCPServerConfigService(session, perm_filter)
    try:
        config = await service.update(config_id, payload)
    except MCPServerConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server config not found: {exc}",
        ) from exc
    except MCPServerConfigValidationError as exc:
        raise _validation_error(exc) from exc
    await session.commit()
    return service.to_read(config)


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_server_config(
    config_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(depends_permissions(MCPServerConfig, Action.DELETE)),
    ],
) -> None:
    service = MCPServerConfigService(session, perm_filter)
    try:
        await service.delete(config_id)
    except MCPServerConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server config not found: {exc}",
        ) from exc
    await session.commit()
