"""HTTP routes for the DB-backed sandbox config resource.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox/sandbox-configs``:
cursor pagination, CRUD (create, read, update, delete), batch read/write, and
count. A sandbox config is the durable intent for a sandbox — the
:class:`SandboxService` reconciles live sandboxes to match it.

The ``session_api_key`` is never exposed in the API (it is encrypted at rest
and revealed only to the sandbox service).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_config_schemas import (
    SandboxConfigBatchWriteRequest,
    SandboxConfigCreate,
    SandboxConfigRead,
    SandboxConfigSearchFilter,
    SandboxConfigSearchResult,
    SandboxConfigUpdate,
)
from openhands.ev2.sandbox.sandbox_config_service import (
    BatchPermissionDeniedError,
    SandboxConfigNotFoundError,
    SandboxConfigPermissionScopeError,
    SandboxConfigService,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox/sandbox-configs", tags=["sandbox-configs"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxConfigNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxTemplateNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxConfigPermissionScopeError, status.HTTP_403_FORBIDDEN),
    (BatchPermissionDeniedError, status.HTTP_403_FORBIDDEN),
)


def _map_exception_to_status(exc: Exception) -> HTTPException:
    for error, http_status in _ERROR_STATUS:
        if isinstance(exc, error):
            return HTTPException(status_code=http_status, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("", response_model=SandboxConfigSearchResult)
async def search_sandbox_configs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.SEARCH)),
    ],
    search_filter: SandboxConfigSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxConfigSearchResult:
    service = SandboxConfigService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxConfigSearchResult(
        items=[service.to_read(row) for row in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandbox_configs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.SEARCH)),
    ],
    search_filter: SandboxConfigSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = SandboxConfigService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=SandboxConfigRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox_config(
    payload: SandboxConfigCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.CREATE)),
    ],
) -> SandboxConfigRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SandboxConfigService(session, perm_filter)
    try:
        config = await service.create(payload, creator_id=user_id)
    except SandboxTemplateNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    except SandboxConfigPermissionScopeError as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return service.to_read(config)


@router.get("/batch", response_model=BatchReadResult[SandboxConfigRead])
async def get_sandbox_configs_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxConfigRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SandboxConfigService(session, perm_filter)
    configs = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(c) if c is not None else None for c in configs],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxConfigRead])
async def write_sandbox_configs_batch(
    payload: SandboxConfigBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    create_filter: Annotated[
        SearchFilter[SandboxConfig] | None,
        Depends(depends_permissions_or_none(SandboxConfig, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[SandboxConfig] | None,
        Depends(depends_permissions_or_none(SandboxConfig, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[SandboxConfig] | None,
        Depends(depends_permissions_or_none(SandboxConfig, Action.DELETE)),
    ],
) -> BatchWriteResult[SandboxConfigRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SandboxConfigService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, creator_id=user_id)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(c) if c is not None else None for c in results],
    )


@router.get("/{config_id}", response_model=SandboxConfigRead)
async def get_sandbox_config(
    config_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.READ)),
    ],
) -> SandboxConfigRead:
    service = SandboxConfigService(session, perm_filter)
    try:
        config = await service.get(config_id)
    except SandboxConfigNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return service.to_read(config)


@router.patch("/{config_id}", response_model=SandboxConfigRead)
async def update_sandbox_config(
    config_id: uuid.UUID,
    payload: SandboxConfigUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.UPDATE)),
    ],
) -> SandboxConfigRead:
    service = SandboxConfigService(session, perm_filter)
    try:
        config = await service.update(config_id, payload)
    except SandboxConfigNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return service.to_read(config)


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_config(
    config_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.DELETE)),
    ],
) -> None:
    service = SandboxConfigService(session, perm_filter)
    try:
        await service.delete(config_id)
    except SandboxConfigNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
