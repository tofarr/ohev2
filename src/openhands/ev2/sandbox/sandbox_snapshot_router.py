"""HTTP routes for the DB-backed sandbox snapshot resource.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox/sandbox-snapshots``:
cursor pagination, create (multipart), read, delete, batch read/write, and
count. Snapshots are create/read/delete only (no update).

The DB index row is owned by :class:`SandboxSnapshotService` (request-scoped
session). The artifact capture/streaming is delegated to the app-scoped
:class:`SandboxService` (the polymorphic reconciler) resolved from
``app.state``.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotUnsupportedError,
)
from openhands.ev2.sandbox.sandbox_snapshot_models import SandboxSnapshot
from openhands.ev2.sandbox.sandbox_snapshot_schemas import (
    SandboxSnapshotBatchWriteRequest,
    SandboxSnapshotCreate,
    SandboxSnapshotRead,
    SandboxSnapshotSearchFilter,
    SandboxSnapshotSearchResult,
)
from openhands.ev2.sandbox.sandbox_snapshot_service import (
    BatchPermissionDeniedError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotPermissionScopeError,
    SandboxSnapshotService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox/sandbox-snapshots", tags=["sandbox-snapshots"])


async def get_sandbox_service(request: Request) -> SandboxService:
    """Resolve the app-scoped sandbox service (started in the app lifespan)."""
    service = getattr(request.app.state, "sandbox_service", None)
    if not isinstance(service, SandboxService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox service is not available.",
        )
    return service


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxSnapshotNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxSnapshotPermissionScopeError, status.HTTP_403_FORBIDDEN),
    (SandboxSnapshotUnsupportedError, status.HTTP_501_NOT_IMPLEMENTED),
    (SandboxNotFoundError, status.HTTP_404_NOT_FOUND),
    (BatchPermissionDeniedError, status.HTTP_403_FORBIDDEN),
)


def _map_exception_to_status(exc: Exception) -> HTTPException:
    for error, http_status in _ERROR_STATUS:
        if isinstance(exc, error):
            return HTTPException(status_code=http_status, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("", response_model=SandboxSnapshotSearchResult)
async def search_sandbox_snapshots(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.SEARCH)),
    ],
    search_filter: SandboxSnapshotSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxSnapshotSearchResult:
    service = SandboxSnapshotService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxSnapshotSearchResult(
        items=[service.to_read(row) for row in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandbox_snapshots(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.SEARCH)),
    ],
    search_filter: SandboxSnapshotSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = SandboxSnapshotService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=SandboxSnapshotRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox_snapshot(
    request: Request,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.CREATE)),
    ],
    sandbox_perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(depends_permissions(SandboxConfig, Action.USE)),
    ],
    sandbox_template_id: Annotated[uuid.UUID, Form()],
    sandbox_id: Annotated[uuid.UUID | None, Form()] = None,
    schema_type: Annotated[str | None, Form(max_length=255)] = None,
    file: Annotated[UploadFile | None, File()] = None,
) -> SandboxSnapshotRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    file_data = await file.read() if file is not None else None
    try:
        payload = SandboxSnapshotCreate(
            sandbox_template_id=sandbox_template_id,
            sandbox_id=sandbox_id,
            schema_type=schema_type,
            file_data=file_data,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    sandbox_service = await get_sandbox_service(request)
    snapshot_service = SandboxSnapshotService(session, perm_filter)
    try:
        if payload.sandbox_id is not None:
            download_url, size_bytes = await sandbox_service.capture_snapshot(
                str(payload.sandbox_id),
                sandbox_perm_filter=sandbox_perm_filter,
            )
            snapshot = await snapshot_service.create_from_sandbox(
                payload,
                creator_id=user_id,
                download_url=download_url,
                size_bytes=size_bytes,
            )
        else:
            download_url, size_bytes = await sandbox_service.import_snapshot_file(
                payload.file_data,
                schema_type=payload.schema_type,
            )
            snapshot = await snapshot_service.create_from_file(
                payload,
                creator_id=user_id,
                download_url=download_url,
                size_bytes=size_bytes,
            )
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return snapshot_service.to_read(
        snapshot,
        download_url=f"/sandbox/sandbox-snapshots/{snapshot.id}/download",
    )


@router.get("/batch", response_model=BatchReadResult[SandboxSnapshotRead])
async def get_sandbox_snapshots_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxSnapshotRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SandboxSnapshotService(session, perm_filter)
    snapshots = await service.get_many(ids)
    return BatchReadResult(
        items=[
            service.to_read(
                s,
                download_url=f"/sandbox/sandbox-snapshots/{s.id}/download",
            )
            if s is not None
            else None
            for s in snapshots
        ],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxSnapshotRead])
async def write_sandbox_snapshots_batch(
    payload: SandboxSnapshotBatchWriteRequest,
    session: SessionDep,
    delete_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.DELETE)),
    ],
) -> BatchWriteResult[SandboxSnapshotRead]:
    service = SandboxSnapshotService(session)
    perm_filters = {Action.DELETE: delete_filter}
    try:
        await service.apply_batch(payload.operations, perm_filters)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return BatchWriteResult(items=[])


@router.get("/{snapshot_id}", response_model=SandboxSnapshotRead)
async def get_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
) -> SandboxSnapshotRead:
    service = SandboxSnapshotService(session, perm_filter)
    try:
        snapshot = await service.get(snapshot_id)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return service.to_read(
        snapshot,
        download_url=f"/sandbox/sandbox-snapshots/{snapshot.id}/download",
    )


@router.get("/{snapshot_id}/download")
async def download_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
) -> StreamingResponse:
    service = SandboxSnapshotService(session, perm_filter)
    try:
        snapshot = await service.get(snapshot_id)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    sandbox_service = await get_sandbox_service(request)
    stream = await sandbox_service.stream_snapshot(str(snapshot.id))
    return StreamingResponse(
        stream,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{snapshot.id}.tar.gz"'},
    )


@router.delete("/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.DELETE)),
    ],
) -> None:
    service = SandboxSnapshotService(session, perm_filter)
    try:
        snapshot = await service.delete(snapshot_id)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    sandbox_service = await get_sandbox_service(request)
    await sandbox_service.delete_snapshot_artifact(str(snapshot.id))
    await session.commit()
