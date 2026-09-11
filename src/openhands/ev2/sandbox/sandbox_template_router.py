"""HTTP routes for the DB-backed sandbox template resource.

Uniform REST surface (AGENTS.md §3) mounted under ``/sandbox/sandbox-templates``:
cursor pagination, CRUD (create, read, update, delete), batch read/write, and
count. Templates are mutable — unlike the prior image-inventory model they can
be updated via ``PATCH`` without a redeploy.

Templates are DB-backed (not provider inventory), so handlers use a
request-scoped DB session and the :class:`SandboxTemplateService`.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.sandbox.sandbox_service import (
    BatchPermissionDeniedError,
    SandboxService,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
    SandboxTemplatePermissionScopeError,
)
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.sandbox.sandbox_template_schemas import (
    SandboxTemplateBatchWriteRequest,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxTemplateSearchFilter,
    SandboxTemplateSearchResult,
    SandboxTemplateUpdate,
)
from openhands.ev2.sandbox.sandbox_template_service import (
    SandboxTemplateInUseError,
    SandboxTemplateService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/sandbox/sandbox-templates", tags=["sandbox-templates"])


async def get_optional_sandbox_service(request: Request) -> SandboxService | None:
    """Resolve the app-scoped sandbox service, or ``None`` when unavailable.

    The sandbox service is started in the app lifespan and stashed on
    ``app.state``. It is absent when the lifespan has not run (e.g. some test
    setups); in that case template mutations skip the provider refresh rather
    than failing the request.
    """
    service = getattr(request.app.state, "sandbox_service", None)
    return service if isinstance(service, SandboxService) else None


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


_ERROR_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (SandboxTemplateNotFoundError, status.HTTP_404_NOT_FOUND),
    (SandboxTemplatePermissionScopeError, status.HTTP_403_FORBIDDEN),
    (SandboxTemplateConflictError, status.HTTP_409_CONFLICT),
    (SandboxTemplateInUseError, status.HTTP_409_CONFLICT),
    (BatchPermissionDeniedError, status.HTTP_403_FORBIDDEN),
)


def _map_exception_to_status(exc: Exception) -> HTTPException:
    for error, http_status in _ERROR_STATUS:
        if isinstance(exc, error):
            return HTTPException(status_code=http_status, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("", response_model=SandboxTemplateSearchResult)
async def search_sandbox_templates(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.SEARCH)),
    ],
    search_filter: SandboxTemplateSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxTemplateSearchResult:
    service = SandboxTemplateService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxTemplateSearchResult(
        items=[service.to_read(row) for row in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_sandbox_templates(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.SEARCH)),
    ],
    search_filter: SandboxTemplateSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = SandboxTemplateService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=SandboxTemplateRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox_template(
    payload: SandboxTemplateCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.CREATE)),
    ],
    sandbox_service: Annotated[SandboxService | None, Depends(get_optional_sandbox_service)],
) -> SandboxTemplateRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SandboxTemplateService(session, perm_filter, sandbox_service=sandbox_service)
    try:
        template = await service.create(payload, creator_id=user_id)
    except SandboxTemplatePermissionScopeError as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return service.to_read(template)


@router.get("/batch", response_model=BatchReadResult[SandboxTemplateRead])
async def get_sandbox_templates_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxTemplateRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SandboxTemplateService(session, perm_filter)
    templates = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(t) if t is not None else None for t in templates],
    )


@router.post("/batch", response_model=BatchWriteResult[SandboxTemplateRead])
async def write_sandbox_templates_batch(
    payload: SandboxTemplateBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    create_filter: Annotated[
        SearchFilter[SandboxTemplate] | None,
        Depends(depends_permissions_or_none(SandboxTemplate, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[SandboxTemplate] | None,
        Depends(depends_permissions_or_none(SandboxTemplate, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[SandboxTemplate] | None,
        Depends(depends_permissions_or_none(SandboxTemplate, Action.DELETE)),
    ],
    sandbox_service: Annotated[SandboxService | None, Depends(get_optional_sandbox_service)],
) -> BatchWriteResult[SandboxTemplateRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SandboxTemplateService(session, sandbox_service=sandbox_service)
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
        items=[service.to_read(t) if t is not None else None for t in results],
    )


@router.get("/{template_id}", response_model=SandboxTemplateRead)
async def get_sandbox_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.READ)),
    ],
) -> SandboxTemplateRead:
    service = SandboxTemplateService(session, perm_filter)
    try:
        template = await service.get(template_id)
    except SandboxTemplateNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    return service.to_read(template)


@router.patch("/{template_id}", response_model=SandboxTemplateRead)
async def update_sandbox_template(
    template_id: uuid.UUID,
    payload: SandboxTemplateUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.UPDATE)),
    ],
    sandbox_service: Annotated[SandboxService | None, Depends(get_optional_sandbox_service)],
) -> SandboxTemplateRead:
    service = SandboxTemplateService(session, perm_filter, sandbox_service=sandbox_service)
    try:
        template = await service.update(template_id, payload)
    except SandboxTemplateNotFoundError as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
    return service.to_read(template)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.DELETE)),
    ],
    sandbox_service: Annotated[SandboxService | None, Depends(get_optional_sandbox_service)],
) -> None:
    service = SandboxTemplateService(session, perm_filter, sandbox_service=sandbox_service)
    try:
        await service.delete(template_id)
    except (SandboxTemplateNotFoundError, SandboxTemplateInUseError) as exc:
        raise _map_exception_to_status(exc) from exc
    await session.commit()
