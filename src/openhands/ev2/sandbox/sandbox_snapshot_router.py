"""HTTP routes for the sandbox snapshot resource.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox/``: the
collection is ``/sandbox/sandbox-snapshots`` with cursor pagination; create
is ``POST`` (multipart form — a snapshot may be imported from an uploaded
file), retrieve is ``GET``, remove is ``DELETE``, plus batch read/write and
count. Snapshots are create/read/delete only (no update).

Snapshot state is owned by the configured :class:`SandboxService` (a per-app
async context manager), not by a request-scoped session, so handlers resolve
the service from ``app.state`` via ``get_sandbox_service``. The create endpoint
accepts a multipart form with an optional ``file``: when ``sandbox_id`` is
present the service snapshots an existing sandbox; when ``file`` is present
together with ``schema_type`` the service imports the uploaded artifact.

The download endpoint streams the snapshot artifact (``docker save`` for the
Docker implementation) and is the URL surfaced as ``download_url`` on the
snapshot read model.
"""

from __future__ import annotations

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

from openhands.ev2.auth.auth_dependencies import depends_permissions, depends_permissions_or_none
from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxSnapshot
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxSnapshotBatchWriteRequest,
    SandboxSnapshotCreate,
    SandboxSnapshotRead,
    SandboxSnapshotSearchFilter,
    SandboxSnapshotSearchResult,
)
from openhands.ev2.sandbox.sandbox_service import (
    BatchPermissionDeniedError,
    SandboxNotFoundError,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotPermissionScopeError,
    SandboxSnapshotUnsupportedError,
)
from openhands.ev2.sandbox.sandbox_template_router import get_sandbox_service
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox/sandbox-snapshots", tags=["sandbox-snapshots"])


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxSnapshotNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxSnapshotConflictError, status.HTTP_409_CONFLICT),
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
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.SEARCH)),
    ],
    search_filter: SandboxSnapshotSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque id cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxSnapshotSearchResult:
    service = await get_sandbox_service(request)
    snapshots, next_cursor = await service.search_snapshots(
        cursor=cursor,
        limit=limit,
        search_filter=search_filter,
        perm_filter=perm_filter,
    )
    return SandboxSnapshotSearchResult(
        items=[SandboxSnapshotRead.model_validate(s) for s in snapshots],
        next_cursor=next_cursor,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandbox_snapshots(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.SEARCH)),
    ],
    search_filter: SandboxSnapshotSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = await get_sandbox_service(request)
    total = await service.count_snapshots(search_filter=search_filter, perm_filter=perm_filter)
    return CountResult(count=total)


@router.post("", response_model=SandboxSnapshotRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox_snapshot(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.CREATE)),
    ],
    sandbox_perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.USE)),
    ],
    sandbox_id: Annotated[str | None, Form(min_length=1, max_length=255)] = None,
    schema_type: Annotated[str | None, Form(max_length=255)] = None,
    file: Annotated[UploadFile | None, File()] = None,
) -> SandboxSnapshotRead:
    file_data = await file.read() if file is not None else None
    try:
        payload = SandboxSnapshotCreate(
            sandbox_id=sandbox_id,
            schema_type=schema_type,
            file_data=file_data,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    service = await get_sandbox_service(request)
    try:
        snapshot = await service.create_snapshot(
            payload,
            perm_filter=perm_filter,
            sandbox_perm_filter=sandbox_perm_filter,
        )
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    download_url = f"/sandbox/sandbox-snapshots/{snapshot.id}/download"
    return SandboxSnapshotRead.model_validate(
        snapshot.model_copy(update={"download_url": download_url})
    )


@router.get("/batch", response_model=BatchReadResult[SandboxSnapshotRead])
async def get_sandbox_snapshots_batch(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
    ids: Annotated[list[str], Query(default_factory=list)],
) -> BatchReadResult[SandboxSnapshotRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = await get_sandbox_service(request)
    snapshots = await service.get_snapshots(ids, perm_filter=perm_filter)
    return BatchReadResult(
        items=[SandboxSnapshotRead.model_validate(s) if s is not None else None for s in snapshots],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxSnapshotRead])
async def write_sandbox_snapshots_batch(
    payload: SandboxSnapshotBatchWriteRequest,
    request: Request,
    delete_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.DELETE)),
    ],
) -> BatchWriteResult[SandboxSnapshotRead]:
    service = await get_sandbox_service(request)
    perm_filters = {Action.DELETE: delete_filter}
    try:
        results = await service.apply_snapshot_batch(payload.operations, perm_filters)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return BatchWriteResult(
        items=[SandboxSnapshotRead.model_validate(s) if s is not None else None for s in results],
    )


@router.get("/{snapshot_id}", response_model=SandboxSnapshotRead)
async def get_sandbox_snapshot(
    snapshot_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
) -> SandboxSnapshotRead:
    service = await get_sandbox_service(request)
    try:
        snapshot = await service.get_snapshot(snapshot_id, perm_filter=perm_filter)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    download_url = f"/sandbox/sandbox-snapshots/{snapshot.id}/download"
    return SandboxSnapshotRead.model_validate(
        snapshot.model_copy(update={"download_url": download_url})
    )


@router.get("/{snapshot_id}/download")
async def download_sandbox_snapshot(
    snapshot_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.READ)),
    ],
) -> StreamingResponse:
    service = await get_sandbox_service(request)
    try:
        await service.get_snapshot(snapshot_id, perm_filter=perm_filter)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    stream = await service.stream_snapshot(snapshot_id)
    return StreamingResponse(
        stream,
        media_type="application/x-tar",
        headers={"Content-Disposition": f'attachment; filename="{snapshot_id}.tar"'},
    )


@router.delete("/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_snapshot(
    snapshot_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.DELETE)),
    ],
) -> None:
    service = await get_sandbox_service(request)
    try:
        await service.delete_snapshot(snapshot_id, perm_filter=perm_filter)
    except SandboxSnapshotNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
