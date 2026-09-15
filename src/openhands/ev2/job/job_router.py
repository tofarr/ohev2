"""HTTP routes for the job feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/jobs`` with cursor
pagination; create is ``POST``, update is ``PATCH``, retrieve is ``GET``, remove
is ``DELETE``; batch read + batch write and count are also provided. Every
endpoint is guarded by the centralized permission checker (AGENTS.md §9) over
the ``job`` resource; the returned :class:`SearchFilter` scopes the service SQL
to rows the principal may see.

``created_at`` (the partition key) is never exposed on the REST surface —
clients interact by ``id`` alone (partitioning is internal, mirroring the usage
tables).
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
from openhands.ev2.job.job_models import Job
from openhands.ev2.job.job_schemas import (
    JobBatchWriteRequest,
    JobCreate,
    JobRead,
    JobSearchFilter,
    JobSearchResult,
    JobUpdate,
)
from openhands.ev2.job.job_service import (
    BatchPermissionDeniedError,
    JobNotFoundError,
    JobPermissionScopeError,
    JobService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=JobSearchResult)
async def search_jobs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.SEARCH)),
    ],
    search_filter: JobSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> JobSearchResult:
    service = JobService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return JobSearchResult(
        items=[JobRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_jobs(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.SEARCH)),
    ],
    search_filter: JobSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = JobService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=JobRead, status_code=status.HTTP_201_CREATED)
async def create_job(
    payload: JobCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.CREATE)),
    ],
) -> JobRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = JobService(session, perm_filter)
    try:
        job = await service.create(payload, creator_id=user_id)
    except JobPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Job falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return JobRead.model_validate(job)


@router.get("/batch", response_model=BatchReadResult[JobRead])
async def get_jobs_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.READ)),
    ],
    # Declared before `/{job_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[JobRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = JobService(session, perm_filter)
    jobs = await service.get_many(ids)
    return BatchReadResult(
        items=[JobRead.model_validate(j) if j is not None else None for j in jobs],
    )


@router.post("/batch", response_model=BatchWriteResult[JobRead])
async def write_jobs_batch(
    payload: JobBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{job_id}` so the static `/batch`
    # path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[Job] | None,
        Depends(depends_permissions_or_none(Job, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[Job] | None,
        Depends(depends_permissions_or_none(Job, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[Job] | None,
        Depends(depends_permissions_or_none(Job, Action.DELETE)),
    ],
) -> BatchWriteResult[JobRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = JobService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, creator_id=user_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except JobPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Job falls outside your create scope: {exc}",
        ) from exc
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[JobRead.model_validate(j) if j is not None else None for j in results],
    )


@router.get("/{job_id}", response_model=JobRead)
async def get_job(
    job_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.READ)),
    ],
) -> JobRead:
    service = JobService(session, perm_filter)
    try:
        job = await service.get(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {exc}",
        ) from exc
    return JobRead.model_validate(job)


@router.patch("/{job_id}", response_model=JobRead)
async def update_job(
    job_id: uuid.UUID,
    payload: JobUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.UPDATE)),
    ],
) -> JobRead:
    service = JobService(session, perm_filter)
    try:
        job = await service.update(job_id, payload)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {exc}",
        ) from exc
    await session.commit()
    return JobRead.model_validate(job)


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Job],
        Depends(depends_permissions(Job, Action.DELETE)),
    ],
) -> None:
    service = JobService(session, perm_filter)
    try:
        await service.delete(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {exc}",
        ) from exc
    await session.commit()
