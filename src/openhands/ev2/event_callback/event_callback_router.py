"""HTTP routes for the event callback feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/event-callbacks``
with cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, remove is ``DELETE``; batch read + batch write and count are also
provided. Every endpoint is guarded by the centralized permission checker
(AGENTS.md §9) over the ``event_callback`` resource; the returned
:class:`SearchFilter` scopes the service SQL to rows the principal may see.
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
from openhands.ev2.event_callback.event_callback_models import EventCallback
from openhands.ev2.event_callback.event_callback_schemas import (
    EventCallbackBatchWriteRequest,
    EventCallbackCreate,
    EventCallbackRead,
    EventCallbackSearchFilter,
    EventCallbackSearchResult,
    EventCallbackUpdate,
)
from openhands.ev2.event_callback.event_callback_service import (
    BatchPermissionDeniedError,
    EventCallbackLinkInvariantError,
    EventCallbackNotFoundError,
    EventCallbackPermissionScopeError,
    EventCallbackService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/event-callbacks", tags=["event-callbacks"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=EventCallbackSearchResult)
async def search_event_callbacks(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.SEARCH)),
    ],
    search_filter: EventCallbackSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> EventCallbackSearchResult:
    service = EventCallbackService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return EventCallbackSearchResult(
        items=[EventCallbackRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_event_callbacks(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.SEARCH)),
    ],
    search_filter: EventCallbackSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = EventCallbackService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=EventCallbackRead, status_code=status.HTTP_201_CREATED)
async def create_event_callback(
    payload: EventCallbackCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.CREATE)),
    ],
) -> EventCallbackRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = EventCallbackService(session, perm_filter)
    try:
        callback = await service.create(payload, creator_id=user_id)
    except EventCallbackPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Event callback falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return EventCallbackRead.model_validate(callback)


@router.get("/batch", response_model=BatchReadResult[EventCallbackRead])
async def get_event_callbacks_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.READ)),
    ],
    # Declared before `/{callback_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[EventCallbackRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = EventCallbackService(session, perm_filter)
    callbacks = await service.get_many(ids)
    return BatchReadResult(
        items=[EventCallbackRead.model_validate(c) if c is not None else None for c in callbacks],
    )


@router.post("/batch", response_model=BatchWriteResult[EventCallbackRead])
async def write_event_callbacks_batch(
    payload: EventCallbackBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{callback_id}` so the static
    # `/batch` path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[EventCallback] | None,
        Depends(depends_permissions_or_none(EventCallback, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[EventCallback] | None,
        Depends(depends_permissions_or_none(EventCallback, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[EventCallback] | None,
        Depends(depends_permissions_or_none(EventCallback, Action.DELETE)),
    ],
) -> BatchWriteResult[EventCallbackRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = EventCallbackService(session)
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
    except EventCallbackPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Event callback falls outside your create scope: {exc}",
        ) from exc
    except EventCallbackLinkInvariantError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except EventCallbackNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event callback not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[EventCallbackRead.model_validate(c) if c is not None else None for c in results],
    )


@router.get("/{callback_id}", response_model=EventCallbackRead)
async def get_event_callback(
    callback_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.READ)),
    ],
) -> EventCallbackRead:
    service = EventCallbackService(session, perm_filter)
    try:
        callback = await service.get(callback_id)
    except EventCallbackNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event callback not found: {exc}",
        ) from exc
    return EventCallbackRead.model_validate(callback)


@router.patch("/{callback_id}", response_model=EventCallbackRead)
async def update_event_callback(
    callback_id: uuid.UUID,
    payload: EventCallbackUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.UPDATE)),
    ],
) -> EventCallbackRead:
    service = EventCallbackService(session, perm_filter)
    try:
        callback = await service.update(callback_id, payload)
    except EventCallbackNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event callback not found: {exc}",
        ) from exc
    except EventCallbackLinkInvariantError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    await session.commit()
    return EventCallbackRead.model_validate(callback)


@router.delete("/{callback_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event_callback(
    callback_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[EventCallback],
        Depends(depends_permissions(EventCallback, Action.DELETE)),
    ],
) -> None:
    service = EventCallbackService(session, perm_filter)
    try:
        await service.delete(callback_id)
    except EventCallbackNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event callback not found: {exc}",
        ) from exc
    await session.commit()
