"""HTTP routes for sandbox templates, sandboxes, and snapshots."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    UserId,
    depends_permissions,
    depends_permissions_or_none,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxSnapshot, SandboxTemplate
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxBatchWriteRequest,
    SandboxCreate,
    SandboxRead,
    SandboxSearchFilter,
    SandboxSearchResult,
    SandboxSnapshotBatchWriteRequest,
    SandboxSnapshotCreate,
    SandboxSnapshotRead,
    SandboxSnapshotSearchFilter,
    SandboxSnapshotSearchResult,
    SandboxSnapshotUpdate,
    SandboxTemplateBatchWriteRequest,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxTemplateSearchFilter,
    SandboxTemplateSearchResult,
    SandboxTemplateUpdate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    BatchPermissionDeniedError,
    SandboxInvalidStateError,
    SandboxNotFoundError,
    SandboxPermissionScopeError,
    SandboxService,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotPermissionScopeError,
    SandboxSnapshotService,
    SandboxTemplateNotFoundError,
    SandboxTemplatePermissionScopeError,
    SandboxTemplateService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import ALL, SearchFilter

sandbox_template_router = APIRouter(prefix="/sandbox-templates", tags=["sandbox-templates"])
sandbox_router = APIRouter(prefix="/sandboxes", tags=["sandboxes"])
sandbox_snapshot_router = APIRouter(prefix="/sandbox-snapshots", tags=["sandbox-snapshots"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _require_user(user_id: uuid.UUID | None) -> uuid.UUID:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Authentication required."
        )
    return user_id


def _not_found(exc: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@sandbox_template_router.get("", response_model=SandboxTemplateSearchResult)
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
    templates, next_cursor = await service.search(
        cursor=_cursor(cursor) if cursor is not None else None,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxTemplateSearchResult(
        items=[SandboxTemplateRead.model_validate(t) for t in templates],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@sandbox_template_router.get("/count", response_model=CountResult)
async def count_sandbox_templates(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.SEARCH)),
    ],
    search_filter: SandboxTemplateSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    total = await SandboxTemplateService(session, perm_filter).count(search_filter)
    return CountResult(count=total)


@sandbox_template_router.post(
    "",
    response_model=SandboxTemplateRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_sandbox_template(
    payload: SandboxTemplateCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate],
        Depends(depends_permissions(SandboxTemplate, Action.CREATE)),
    ],
) -> SandboxTemplateRead:
    try:
        template = await SandboxTemplateService(session, perm_filter).create(
            payload,
            user_id=_require_user(user_id),
        )
    except SandboxTemplatePermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return SandboxTemplateRead.model_validate(template)


@sandbox_template_router.get("/batch", response_model=BatchReadResult[SandboxTemplateRead])
async def get_sandbox_templates_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.READ))
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxTemplateRead]:
    if len(ids) > 100:
        raise HTTPException(status_code=422, detail="ids: at most 100 ids are allowed.")
    templates = await SandboxTemplateService(session, perm_filter).get_many(ids)
    return BatchReadResult(
        items=[SandboxTemplateRead.model_validate(t) if t is not None else None for t in templates]
    )


@sandbox_template_router.post("/batch", response_model=BatchWriteResult[SandboxTemplateRead])
async def write_sandbox_templates_batch(
    payload: SandboxTemplateBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
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
) -> BatchWriteResult[SandboxTemplateRead]:
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await SandboxTemplateService(session).apply_batch(
            payload.operations,
            perm_filters,
            user_id=_require_user(user_id),
        )
    except BatchPermissionDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return BatchWriteResult(
        items=[SandboxTemplateRead.model_validate(t) if t is not None else None for t in results]
    )


@sandbox_template_router.get("/{template_id}", response_model=SandboxTemplateRead)
async def get_sandbox_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.READ))
    ],
) -> SandboxTemplateRead:
    try:
        template = await SandboxTemplateService(session, perm_filter).get(template_id)
    except SandboxTemplateNotFoundError as exc:
        raise _not_found(exc) from exc
    return SandboxTemplateRead.model_validate(template)


@sandbox_template_router.patch("/{template_id}", response_model=SandboxTemplateRead)
async def update_sandbox_template(
    template_id: uuid.UUID,
    payload: SandboxTemplateUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.UPDATE))
    ],
) -> SandboxTemplateRead:
    try:
        template = await SandboxTemplateService(session, perm_filter).update(template_id, payload)
    except SandboxTemplateNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()
    return SandboxTemplateRead.model_validate(template)


@sandbox_template_router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.DELETE))
    ],
) -> None:
    try:
        await SandboxTemplateService(session, perm_filter).delete(template_id)
    except SandboxTemplateNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()


@sandbox_router.get("", response_model=SandboxSearchResult)
async def search_sandboxes(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.SEARCH))
    ],
    search_filter: SandboxSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SandboxSearchResult:
    sandboxes, next_cursor = await SandboxService(session, perm_filter).search(
        cursor=_cursor(cursor) if cursor is not None else None,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxSearchResult(
        items=[SandboxRead.model_validate(s) for s in sandboxes],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@sandbox_router.get("/count", response_model=CountResult)
async def count_sandboxes(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.SEARCH))
    ],
    search_filter: SandboxSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    total = await SandboxService(session, perm_filter).count(search_filter)
    return CountResult(count=total)


@sandbox_router.post("", response_model=SandboxRead, status_code=status.HTTP_201_CREATED)
async def create_sandbox(
    payload: SandboxCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.CREATE))
    ],
    template_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.READ))
    ],
    snapshot_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.READ)),
    ],
) -> SandboxRead:
    if payload.snapshot_id is not None and snapshot_filter is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Snapshot read denied.")
    try:
        sandbox = await SandboxService(session, perm_filter).create(
            payload,
            user_id=_require_user(user_id),
            template_filter=template_filter,
            snapshot_filter=snapshot_filter or ALL,
        )
    except (SandboxTemplateNotFoundError, SandboxSnapshotNotFoundError) as exc:
        raise _not_found(exc) from exc
    except (SandboxPermissionScopeError, SandboxInvalidStateError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return SandboxRead.model_validate(sandbox)


@sandbox_router.get("/batch", response_model=BatchReadResult[SandboxRead])
async def get_sandboxes_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.READ))
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxRead]:
    if len(ids) > 100:
        raise HTTPException(status_code=422, detail="ids: at most 100 ids are allowed.")
    sandboxes = await SandboxService(session, perm_filter).get_many(ids)
    return BatchReadResult(
        items=[SandboxRead.model_validate(s) if s is not None else None for s in sandboxes]
    )


@sandbox_router.post("/batch", response_model=BatchWriteResult[SandboxRead])
async def write_sandboxes_batch(
    payload: SandboxBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    create_filter: Annotated[
        SearchFilter[Sandbox] | None,
        Depends(depends_permissions_or_none(Sandbox, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[Sandbox] | None,
        Depends(depends_permissions_or_none(Sandbox, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[Sandbox] | None,
        Depends(depends_permissions_or_none(Sandbox, Action.DELETE)),
    ],
    template_filter: Annotated[
        SearchFilter[SandboxTemplate], Depends(depends_permissions(SandboxTemplate, Action.READ))
    ],
    snapshot_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.READ)),
    ],
) -> BatchWriteResult[SandboxRead]:
    if snapshot_filter is None and any(
        op.op == "create" and op.data.snapshot_id is not None for op in payload.operations
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Snapshot read denied.")
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await SandboxService(session).apply_batch(
            payload.operations,
            perm_filters,
            user_id=_require_user(user_id),
            template_filter=template_filter,
            snapshot_filter=snapshot_filter or ALL,
        )
    except (
        BatchPermissionDeniedError,
        SandboxPermissionScopeError,
        SandboxInvalidStateError,
    ) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except (
        SandboxTemplateNotFoundError,
        SandboxSnapshotNotFoundError,
        SandboxNotFoundError,
    ) as exc:
        raise _not_found(exc) from exc
    await session.commit()
    return BatchWriteResult(
        items=[SandboxRead.model_validate(s) if s is not None else None for s in results]
    )


@sandbox_router.get("/{sandbox_id}", response_model=SandboxRead)
async def get_sandbox(
    sandbox_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.READ))
    ],
) -> SandboxRead:
    try:
        sandbox = await SandboxService(session, perm_filter).get(sandbox_id)
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    return SandboxRead.model_validate(sandbox)


@sandbox_router.patch("/{sandbox_id}", response_model=SandboxRead)
async def update_sandbox(
    sandbox_id: uuid.UUID,
    payload: SandboxUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.UPDATE))
    ],
) -> SandboxRead:
    try:
        sandbox = await SandboxService(session, perm_filter).update(sandbox_id, payload)
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()
    return SandboxRead.model_validate(sandbox)


@sandbox_router.post("/{sandbox_id}/activate", response_model=SandboxRead)
async def activate_sandbox(
    sandbox_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.USE))
    ],
) -> SandboxRead:
    try:
        sandbox = await SandboxService(session, perm_filter).activate(sandbox_id)
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    except SandboxInvalidStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    return SandboxRead.model_validate(sandbox)


@sandbox_router.post("/{sandbox_id}/deactivate", response_model=SandboxRead)
async def deactivate_sandbox(
    sandbox_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.USE))
    ],
) -> SandboxRead:
    try:
        sandbox = await SandboxService(session, perm_filter).deactivate(sandbox_id)
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    except SandboxInvalidStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    return SandboxRead.model_validate(sandbox)


@sandbox_router.delete("/{sandbox_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox(
    sandbox_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.DELETE))
    ],
) -> None:
    try:
        await SandboxService(session, perm_filter).delete(sandbox_id)
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()


@sandbox_snapshot_router.get("", response_model=SandboxSnapshotSearchResult)
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
    snapshots, next_cursor = await SandboxSnapshotService(session, perm_filter).search(
        cursor=_cursor(cursor) if cursor is not None else None,
        limit=limit,
        search_filter=search_filter,
    )
    return SandboxSnapshotSearchResult(
        items=[SandboxSnapshotRead.model_validate(s) for s in snapshots],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@sandbox_snapshot_router.get("/count", response_model=CountResult)
async def count_sandbox_snapshots(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.SEARCH)),
    ],
    search_filter: SandboxSnapshotSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    total = await SandboxSnapshotService(session, perm_filter).count(search_filter)
    return CountResult(count=total)


@sandbox_snapshot_router.post(
    "",
    response_model=SandboxSnapshotRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_sandbox_snapshot(
    payload: SandboxSnapshotCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot],
        Depends(depends_permissions(SandboxSnapshot, Action.CREATE)),
    ],
    sandbox_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.USE))
    ],
) -> SandboxSnapshotRead:
    try:
        snapshot = await SandboxSnapshotService(session, perm_filter).create(
            payload,
            user_id=_require_user(user_id),
            sandbox_filter=sandbox_filter,
        )
    except SandboxNotFoundError as exc:
        raise _not_found(exc) from exc
    except SandboxSnapshotPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return SandboxSnapshotRead.model_validate(snapshot)


@sandbox_snapshot_router.get("/batch", response_model=BatchReadResult[SandboxSnapshotRead])
async def get_sandbox_snapshots_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot], Depends(depends_permissions(SandboxSnapshot, Action.READ))
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SandboxSnapshotRead]:
    if len(ids) > 100:
        raise HTTPException(status_code=422, detail="ids: at most 100 ids are allowed.")
    snapshots = await SandboxSnapshotService(session, perm_filter).get_many(ids)
    return BatchReadResult(
        items=[SandboxSnapshotRead.model_validate(s) if s is not None else None for s in snapshots]
    )


@sandbox_snapshot_router.post("/batch", response_model=BatchWriteResult[SandboxSnapshotRead])
async def write_sandbox_snapshots_batch(
    payload: SandboxSnapshotBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    create_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[SandboxSnapshot] | None,
        Depends(depends_permissions_or_none(SandboxSnapshot, Action.DELETE)),
    ],
    sandbox_filter: Annotated[
        SearchFilter[Sandbox], Depends(depends_permissions(Sandbox, Action.USE))
    ],
) -> BatchWriteResult[SandboxSnapshotRead]:
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await SandboxSnapshotService(session).apply_batch(
            payload.operations,
            perm_filters,
            user_id=_require_user(user_id),
            sandbox_filter=sandbox_filter,
        )
    except (BatchPermissionDeniedError, SandboxSnapshotPermissionScopeError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except (SandboxNotFoundError, SandboxSnapshotNotFoundError) as exc:
        raise _not_found(exc) from exc
    await session.commit()
    return BatchWriteResult(
        items=[SandboxSnapshotRead.model_validate(s) if s is not None else None for s in results]
    )


@sandbox_snapshot_router.get("/{snapshot_id}", response_model=SandboxSnapshotRead)
async def get_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot], Depends(depends_permissions(SandboxSnapshot, Action.READ))
    ],
) -> SandboxSnapshotRead:
    try:
        snapshot = await SandboxSnapshotService(session, perm_filter).get(snapshot_id)
    except SandboxSnapshotNotFoundError as exc:
        raise _not_found(exc) from exc
    return SandboxSnapshotRead.model_validate(snapshot)


@sandbox_snapshot_router.patch("/{snapshot_id}", response_model=SandboxSnapshotRead)
async def update_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    payload: SandboxSnapshotUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot], Depends(depends_permissions(SandboxSnapshot, Action.UPDATE))
    ],
) -> SandboxSnapshotRead:
    try:
        snapshot = await SandboxSnapshotService(session, perm_filter).update(snapshot_id, payload)
    except SandboxSnapshotNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()
    return SandboxSnapshotRead.model_validate(snapshot)


@sandbox_snapshot_router.delete("/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_snapshot(
    snapshot_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SandboxSnapshot], Depends(depends_permissions(SandboxSnapshot, Action.DELETE))
    ],
) -> None:
    try:
        await SandboxSnapshotService(session, perm_filter).delete(snapshot_id)
    except SandboxSnapshotNotFoundError as exc:
        raise _not_found(exc) from exc
    await session.commit()


__all__ = [
    "sandbox_router",
    "sandbox_snapshot_router",
    "sandbox_template_router",
]
