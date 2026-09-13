"""HTTP routes for the event feature.

Events are nested under conversations (AGENTS.md §3): create is
``POST /conversations/{id}/events``, list is ``GET /conversations/{id}/events``
with cursor pagination, retrieve is
``GET /conversations/{conv_id}/events/{event_id}``, and the full-body
download is ``GET /conversations/{conv_id}/events/{event_id}/body``. Events
are immutable — no update/delete (delete is partition retention only).

Handlers validate, call the service, and serialize. Every endpoint is guarded
by the centralized permission checker; the returned :class:`SearchFilter`
scopes the service. The backing store + body cap resolve from the cached
:class:`~openhands.ev2.config.AppConfig` — no lifespan wiring, so the
filesystem-default store is constructed lazily on first access.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.config import get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.event.event_models import Event
from openhands.ev2.event.event_schemas import (
    EventCreate,
    EventRead,
    EventSearchFilter,
    EventSearchResult,
)
from openhands.ev2.event.event_service import (
    ConversationNotFoundError,
    EventBodyNotFoundError,
    EventNotFoundError,
    EventPermissionScopeError,
    EventService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(
    prefix="/conversations/{conversation_id}/events",
    tags=["events"],
)


def _cursor(value: str) -> tuple[datetime, uuid.UUID]:
    """Parse an opaque ``<iso-timestamp>|<uuid>`` cursor, or 400 on junk."""
    ts, sep, eid = value.partition("|")
    if not sep:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected '<iso-timestamp>|<uuid>'.",
        )
    try:
        return datetime.fromisoformat(ts), uuid.UUID(eid)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected '<iso-timestamp>|<uuid>'.",
        ) from exc


def _encode_cursor(cursor: tuple[datetime, uuid.UUID]) -> str:
    """The opaque ``<iso-timestamp>|<uuid>`` cursor for the next page."""
    return f"{cursor[0].isoformat()}|{cursor[1]}"


def _service(session: SessionDep, perm_filter: SearchFilter[Event]) -> EventService:
    """Build the per-request service from config (store, cap) + scope."""
    cfg = get_config()
    return EventService(
        session,
        perm_filter,
        store=cfg.get_event_store(),
        body_cap_bytes=cfg.event.body_cap_bytes,
    )


@router.post("", response_model=EventRead, status_code=status.HTTP_201_CREATED)
async def create_event(
    conversation_id: uuid.UUID,
    payload: EventCreate,
    session: SessionDep,
    # The ingestion path also publishes events; sandboxes call the webhook
    # adapter (``/webhooks/...``) instead. Authorization is the standard
    # role-policy filter, matching every other route.
    perm_filter: Annotated[
        SearchFilter[Event],
        Depends(depends_permissions(Event, Action.CREATE)),
    ],
) -> EventRead:
    service = _service(session, perm_filter)
    try:
        event = await service.create(conversation_id, payload)
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    except EventPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Event falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return EventRead.model_validate(event)


@router.get("", response_model=EventSearchResult)
async def search_events(
    conversation_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Event], Depends(depends_permissions(Event, Action.SEARCH))],
    # Bare `Depends()` lets FastAPI explode the filter model's fields as
    # query params.
    search_filter: EventSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> EventSearchResult:
    service = _service(session, perm_filter)
    parsed_cursor = _cursor(cursor) if cursor is not None else None
    events, next_cursor = await service.search_events(
        conversation_id,
        cursor=parsed_cursor,
        limit=limit,
        search_filter=search_filter,
    )
    return EventSearchResult(
        items=[EventRead.model_validate(e) for e in events],
        next_cursor=_encode_cursor(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/{event_id}", response_model=EventRead)
async def get_event(
    conversation_id: uuid.UUID,
    event_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Event], Depends(depends_permissions(Event, Action.READ))],
) -> EventRead:
    service = _service(session, perm_filter)
    try:
        event = await service.get(conversation_id, event_id)
    except EventNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event not found: {exc}",
        ) from exc
    return EventRead.model_validate(event)


@router.get("/{event_id}/body")
async def get_event_body(
    conversation_id: uuid.UUID,
    event_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Event], Depends(depends_permissions(Event, Action.READ))],
) -> Response:
    """Download the event's full body.

    Not-truncated events return their row payload; truncated ones resolve the
    derivable storage key against the configured backing store. 404 when the
    object is missing or no store is configured.
    """
    service = _service(session, perm_filter)
    try:
        body = await service.get_body(conversation_id, event_id)
    except EventNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event not found: {exc}",
        ) from exc
    except EventBodyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event body not found: {exc}",
        ) from exc
    return Response(content=body, media_type="application/json")
