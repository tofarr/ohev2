"""HTTP routes for the sandbox feature.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox/``: the
collection is ``/sandbox/sandbox-templates`` with cursor pagination; create
is ``POST``, retrieve is ``GET``, remove is ``DELETE``, plus batch read/write
and count. Templates are functionally immutable (no ``PATCH``): the batch
write accepts create and delete operations only.

Template state is owned by the configured :class:`SandboxService` (a
per-app async context manager), not by a request-scoped session, so handlers
resolve the service from ``app.state`` and call it directly.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from openhands.ev2.auth.auth_dependencies import depends_permissions, depends_permissions_or_none
from openhands.ev2.sandbox.sandbox_models import SandboxTemplate
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxTemplateBatchWriteRequest,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxTemplateSearchFilter,
    SandboxTemplateSearchResult,
)
from openhands.ev2.sandbox.sandbox_service import (
    BatchPermissionDeniedError,
    SandboxService,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
    SandboxTemplatePermissionScopeError,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox/sandbox-templates", tags=["sandbox-templates"])


async def get_sandbox_service(request: Request) -> SandboxService:
    """Resolve the app-scoped sandbox service (started in the app lifespan)."""
    service = getattr(request.app.state, "sandbox_service", None)
    if not isinstance(service, SandboxService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox service is not available.",
        )
    return service


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxTemplateNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxTemplateConflictError, status.HTTP_409_CONFLICT),
    (SandboxTemplatePermissionScopeError, status.HTTP_403_FORBIDDEN),
    (BatchPermissionDeniedError, status.HTTP_403_FORBIDDEN),
)


def _map_exception_to_status(exc: Exception) -> HTTPException:
    for error, http_status in _ERROR_STATUS:
        if isinstance(exc, error):
            return HTTPException(status_code=http_status, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("", response_model=SandboxTemplateSearchResult)
async def search_sandbox_templates(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.SEARCH)),
    ],
    search_filter: SandboxTemplateSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque id cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxTemplateSearchResult:
    service = await get_sandbox_service(request)
    templates, next_cursor = await service.search_templates(
        cursor=cursor,
        limit=limit,
        search_filter=search_filter,
        perm_filter=perm_filter,
    )
    return SandboxTemplateSearchResult(
        items=[SandboxTemplateRead.model_validate(t) for t in templates],
        next_cursor=next_cursor,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandbox_templates(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.SEARCH)),
    ],
    search_filter: SandboxTemplateSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = await get_sandbox_service(request)
    total = await service.count_templates(search_filter=search_filter, perm_filter=perm_filter)
    return CountResult(count=total)


@router.post("", response_model=SandboxTemplateRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox_template(
    payload: SandboxTemplateCreate,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.CREATE)),
    ],
) -> SandboxTemplateRead:
    service = await get_sandbox_service(request)
    try:
        template = await service.create_template(payload, perm_filter=perm_filter)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return SandboxTemplateRead.model_validate(template)


@router.get("/batch", response_model=BatchReadResult[SandboxTemplateRead])
async def get_sandbox_templates_batch(
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.READ)),
    ],
    ids: Annotated[list[str], Query(default_factory=list)],
) -> BatchReadResult[SandboxTemplateRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = await get_sandbox_service(request)
    templates = await service.get_templates(ids, perm_filter=perm_filter)
    return BatchReadResult(
        items=[SandboxTemplateRead.model_validate(t) if t is not None else None for t in templates],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxTemplateRead])
async def write_sandbox_templates_batch(
    payload: SandboxTemplateBatchWriteRequest,
    request: Request,
    create_filter: Annotated[
        SearchFilter[SandboxTemplate] | None,
        Depends(depends_permissions_or_none(SandboxTemplate, Action.CREATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[SandboxTemplate] | None,
        Depends(depends_permissions_or_none(SandboxTemplate, Action.DELETE)),
    ],
) -> BatchWriteResult[SandboxTemplateRead]:
    service = await get_sandbox_service(request)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except Exception as exc:
        raise _map_exception_to_status(exc) from exc
    return BatchWriteResult(
        items=[SandboxTemplateRead.model_validate(t) if t is not None else None for t in results],
    )


@router.get("/{template_id}", response_model=SandboxTemplateRead)
async def get_sandbox_template(
    template_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.READ)),
    ],
) -> SandboxTemplateRead:
    service = await get_sandbox_service(request)
    try:
        template = await service.get_template(template_id, perm_filter=perm_filter)
    except SandboxTemplateNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return SandboxTemplateRead.model_validate(template)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_template(
    template_id: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.DELETE)),
    ],
) -> None:
    service = await get_sandbox_service(request)
    try:
        await service.delete_template(template_id, perm_filter=perm_filter)
    except SandboxTemplateNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc


__all__ = ["get_sandbox_service", "router"]
