"""HTTP routes for the conversation feature.

Follows the uniform REST surface (AGENTS.md §3): GET /conversations
(paginated), POST /conversations, GET/PATCH/DELETE /conversations/{id}, plus
the batch read/write endpoints. Handlers validate, call the service, and
serialize — no business logic here. Every endpoint is guarded by the
centralized permission checker (AGENTS.md §9); the returned
:class:`SearchFilter` is passed into the service constructor so
search/update/delete SQL and create payloads are scoped to the principal.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_permissions_or_none,
)
from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import (
    ConversationBatchWriteRequest,
    ConversationCreate,
    ConversationRead,
    ConversationSearchFilter,
    ConversationSearchResult,
    ConversationUpdate,
)
from openhands.ev2.conversation.conversation_service import (
    BatchPermissionDeniedError,
    ConversationNotFoundError,
    ConversationPermissionScopeError,
    ConversationService,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/conversations", tags=["conversations"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=ConversationSearchResult)
async def search_conversations(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.SEARCH))
    ],
    # Bare `Depends()` lets FastAPI explode the filter model's fields as query
    # params.
    search_filter: ConversationSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ConversationSearchResult:
    service = ConversationService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    conversations, next_cursor = await service.search_conversations(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return ConversationSearchResult(
        items=[ConversationRead.model_validate(c) for c in conversations],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_conversations(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.SEARCH))
    ],
    # Declared before `/{conversation_id}` so the static path matches ahead of
    # the UUID path param.
    search_filter: ConversationSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = ConversationService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "",
    response_model=ConversationRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_conversation(
    payload: ConversationCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.CREATE))
    ],
) -> ConversationRead:
    service = ConversationService(session, perm_filter)
    try:
        conversation = await service.create(payload)
    except ConversationPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return ConversationRead.model_validate(conversation)


@router.get(
    "/batch",
    response_model=BatchReadResult[ConversationRead],
)
async def get_conversations_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.READ))
    ],
    # Declared before `/{conversation_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[ConversationRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = ConversationService(session, perm_filter)
    conversations = await service.get_many(ids)
    return BatchReadResult(
        items=[
            ConversationRead.model_validate(c) if c is not None else None for c in conversations
        ],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[ConversationRead],
)
async def write_conversations_batch(
    payload: ConversationBatchWriteRequest,
    session: SessionDep,
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. The service denies per operation when its action
    # has no grant. Declared before `/{conversation_id}` so the static
    # `/batch` path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[Conversation] | None,
        Depends(depends_permissions_or_none(Conversation, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[Conversation] | None,
        Depends(depends_permissions_or_none(Conversation, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[Conversation] | None,
        Depends(depends_permissions_or_none(Conversation, Action.DELETE)),
    ],
) -> BatchWriteResult[ConversationRead]:
    service = ConversationService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except ConversationPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation falls outside your create scope: {exc}",
        ) from exc
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[ConversationRead.model_validate(c) if c is not None else None for c in results],
    )


@router.get("/{conversation_id}", response_model=ConversationRead)
async def get_conversation(
    conversation_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.READ))
    ],
) -> ConversationRead:
    service = ConversationService(session, perm_filter)
    try:
        conversation = await service.get(conversation_id)
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    return ConversationRead.model_validate(conversation)


@router.patch("/{conversation_id}", response_model=ConversationRead)
async def update_conversation(
    conversation_id: uuid.UUID,
    payload: ConversationUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.UPDATE))
    ],
) -> ConversationRead:
    service = ConversationService(session, perm_filter)
    try:
        conversation = await service.update(conversation_id, payload)
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    await session.commit()
    return ConversationRead.model_validate(conversation)


@router.delete("/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(
    conversation_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Conversation], Depends(depends_permissions(Conversation, Action.DELETE))
    ],
) -> None:
    service = ConversationService(session, perm_filter)
    try:
        await service.delete(conversation_id)
    except ConversationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {exc}",
        ) from exc
    await session.commit()
