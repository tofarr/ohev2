"""HTTP routes for the sandbox_v2 sandbox resource.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox_v2/``: the
collection is ``/sandbox_v2/sandboxes`` with cursor pagination; create is
``POST``, retrieve is ``GET``, remove is ``DELETE``, plus batch read/write and
count. The only mutable field is ``desired_status`` (``PATCH /{id}``), which
drives pause/resume.

Sandbox state is owned by the configured :class:`SandboxService` (a per-app
async context manager), not by a request-scoped session, so handlers resolve
the service from ``app.state`` and call it directly. The ``get_sandbox_service``
dependency is shared with the template router.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from openhands.ev2.auth.auth_dependencies import depends_permissions, depends_permissions_or_none
from openhands.ev2.sandbox_v2.sandbox_template_router import get_sandbox_service
from openhands.ev2.sandbox_v2.sandbox_v2_models import Sandbox
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxBatchWriteRequest,
    SandboxCreate,
    SandboxRead,
    SandboxSearchFilter,
    SandboxSearchResult,
    SandboxUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
    BatchPermissionDeniedError,
    SandboxConflictError,
    SandboxNotFoundError,
    SandboxPermissionScopeError,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox_v2/sandboxes", tags=["sandbox-v2-sandboxes"])


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxConflictError, status.HTTP_409_CONFLICT),
    (SandboxPermissionScopeError, status.HTTP_403_FORBIDDEN),
    (BatchPermissionDeniedError, status.HTTP_403_FORBIDDEN),
)


def _map_exception_to_status(exc: Exception) -> HTTPException:
    for error, http_status in _ERROR_STATUS:
        if isinstance(exc, error):
            return HTTPException(status_code=http_status, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("", response_model=SandboxSearchResult)
async def search_sandboxes(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.SEARCH)),
    ],
    search_filter: SandboxSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque id cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxSearchResult:
    service = await get_sandbox_service(request)
    sandboxes = await service.list_sandboxes(perm_filter=perm_filter)
    if search_filter is not None:
        sandboxes = [sb for sb in sandboxes if search_filter.matches(sb)]
    sandboxes.sort(key=lambda sandbox: sandbox.id)
    if cursor is not None:
        sandboxes = [sb for sb in sandboxes if sb.id > cursor]
    page = sandboxes[:limit]
    next_cursor = page[-1].id if len(sandboxes) > limit else None
    return SandboxSearchResult(
        items=[SandboxRead.model_validate(sb) for sb in page],
        next_cursor=next_cursor,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandboxes(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.SEARCH)),
    ],
    search_filter: SandboxSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = await get_sandbox_service(request)
    sandboxes = await service.list_sandboxes(perm_filter=perm_filter)
    if search_filter is not None:
        sandboxes = [sb for sb in sandboxes if search_filter.matches(sb)]
    return CountResult(count=len(sandboxes))


@router.post("", response_model=SandboxRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox(
    payload: SandboxCreate,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.CREATE)),
    ],
) -> SandboxRead:
    service = await get_sandbox_service(request)
    try:
        sandbox = await service.create_sandbox(payload, perm_filter=perm_filter)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return SandboxRead.model_validate(sandbox)


@router.get("/batch", response_model=BatchReadResult[SandboxRead])
async def get_sandboxes_batch(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.READ)),
    ],
    ids: Annotated[list[str], Query(default_factory=list)],
) -> BatchReadResult[SandboxRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = await get_sandbox_service(request)
    sandboxes = await service.get_sandboxes(ids, perm_filter=perm_filter)
    return BatchReadResult(
        items=[SandboxRead.model_validate(sb) if sb is not None else None for sb in sandboxes],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxRead])
async def write_sandboxes_batch(
    payload: SandboxBatchWriteRequest,
    request: Request,
    create_filter: Annotated[
        SearchFilter[Sandbox] | None,
        Depends(depends_permissions_or_none(Sandbox, Action.CREATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[Sandbox] | None,
        Depends(depends_permissions_or_none(Sandbox, Action.DELETE)),
    ],
) -> BatchWriteResult[SandboxRead]:
    service = await get_sandbox_service(request)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_sandbox_batch(payload.operations, perm_filters)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return BatchWriteResult(
        items=[SandboxRead.model_validate(sb) if sb is not None else None for sb in results],
    )


@router.get("/{sandbox_id}", response_model=SandboxRead)
async def get_sandbox(
    sandbox_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.READ)),
    ],
) -> SandboxRead:
    service = await get_sandbox_service(request)
    try:
        sandbox = await service.get_sandbox(sandbox_id, perm_filter=perm_filter)
    except SandboxNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return SandboxRead.model_validate(sandbox)


@router.patch("/{sandbox_id}", response_model=SandboxRead)
async def update_sandbox(
    sandbox_id: str,
    payload: SandboxUpdate,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.UPDATE)),
    ],
) -> SandboxRead:
    service = await get_sandbox_service(request)
    try:
        sandbox = await service.update_sandbox(sandbox_id, payload, perm_filter=perm_filter)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return SandboxRead.model_validate(sandbox)


@router.delete("/{sandbox_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox(
    sandbox_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[Sandbox],
        Depends(depends_permissions(Sandbox, Action.DELETE)),
    ],
) -> None:
    service = await get_sandbox_service(request)
    try:
        await service.delete_sandbox(sandbox_id, perm_filter=perm_filter)
    except SandboxNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc


__all__ = ["router"]
