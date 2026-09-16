"""HTTP routes for the conversation_record feature.

Follows the uniform REST surface (AGENTS.md §3): GET /conversation_records
(paginated), POST /conversation_records, GET/PATCH/DELETE
/conversation_records/{id}, plus the batch read/write endpoints. Handlers
validate, call the service, and serialize — no business logic here. Every
endpoint is guarded by the centralized permission checker (AGENTS.md §9); the
returned :class:`SearchFilter` is passed into the service constructor so
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
from openhands.ev2.conversation_record.conversation_record_models import ConversationRecord
from openhands.ev2.conversation_record.conversation_record_schemas import (
    ConversationRecordBatchWriteRequest,
    ConversationRecordCreate,
    ConversationRecordRead,
    ConversationRecordSearchFilter,
    ConversationRecordSearchResult,
    ConversationRecordUpdate,
)
from openhands.ev2.conversation_record.conversation_record_service import (
    BatchPermissionDeniedError,
    ConversationRecordNotFoundError,
    ConversationRecordPermissionScopeError,
    ConversationRecordService,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/conversation_records", tags=["conversation_records"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=ConversationRecordSearchResult)
async def search_conversation_records(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.SEARCH)),
    ],
    # Bare `Depends()` lets FastAPI explode the filter model's fields as query
    # params.
    search_filter: ConversationRecordSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ConversationRecordSearchResult:
    service = ConversationRecordService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    conversation_records, next_cursor = await service.search_conversation_records(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return ConversationRecordSearchResult(
        items=[ConversationRecordRead.model_validate(c) for c in conversation_records],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_conversation_records(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.SEARCH)),
    ],
    # Declared before `/{conversation_record_id}` so the static path matches ahead of
    # the UUID path param.
    search_filter: ConversationRecordSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = ConversationRecordService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "",
    response_model=ConversationRecordRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_conversation_record(
    payload: ConversationRecordCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.CREATE)),
    ],
) -> ConversationRecordRead:
    service = ConversationRecordService(session, perm_filter)
    try:
        conversation_record = await service.create(payload)
    except ConversationRecordPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation record falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return ConversationRecordRead.model_validate(conversation_record)


@router.get(
    "/batch",
    response_model=BatchReadResult[ConversationRecordRead],
)
async def get_conversation_records_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.READ)),
    ],
    # Declared before `/{conversation_record_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[ConversationRecordRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = ConversationRecordService(session, perm_filter)
    conversation_records = await service.get_many(ids)
    return BatchReadResult(
        items=[
            ConversationRecordRead.model_validate(c) if c is not None else None
            for c in conversation_records
        ],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[ConversationRecordRead],
)
async def write_conversation_records_batch(
    payload: ConversationRecordBatchWriteRequest,
    session: SessionDep,
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. The service denies per operation when its action
    # has no grant. Declared before `/{conversation_record_id}` so the static
    # `/batch` path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[ConversationRecord] | None,
        Depends(depends_permissions_or_none(ConversationRecord, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[ConversationRecord] | None,
        Depends(depends_permissions_or_none(ConversationRecord, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[ConversationRecord] | None,
        Depends(depends_permissions_or_none(ConversationRecord, Action.DELETE)),
    ],
) -> BatchWriteResult[ConversationRecordRead]:
    service = ConversationRecordService(session)
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
    except ConversationRecordPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation record falls outside your create scope: {exc}",
        ) from exc
    except ConversationRecordNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation record not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[
            ConversationRecordRead.model_validate(c) if c is not None else None for c in results
        ],
    )


@router.get("/{conversation_record_id}", response_model=ConversationRecordRead)
async def get_conversation_record(
    conversation_record_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.READ)),
    ],
) -> ConversationRecordRead:
    service = ConversationRecordService(session, perm_filter)
    try:
        conversation_record = await service.get(conversation_record_id)
    except ConversationRecordNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation record not found: {exc}",
        ) from exc
    return ConversationRecordRead.model_validate(conversation_record)


@router.patch("/{conversation_record_id}", response_model=ConversationRecordRead)
async def update_conversation_record(
    conversation_record_id: uuid.UUID,
    payload: ConversationRecordUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.UPDATE)),
    ],
) -> ConversationRecordRead:
    service = ConversationRecordService(session, perm_filter)
    try:
        conversation_record = await service.update(conversation_record_id, payload)
    except ConversationRecordNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation record not found: {exc}",
        ) from exc
    await session.commit()
    return ConversationRecordRead.model_validate(conversation_record)


@router.delete("/{conversation_record_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation_record(
    conversation_record_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationRecord],
        Depends(depends_permissions(ConversationRecord, Action.DELETE)),
    ],
) -> None:
    service = ConversationRecordService(session, perm_filter)
    try:
        await service.delete(conversation_record_id)
    except ConversationRecordNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation record not found: {exc}",
        ) from exc
    await session.commit()
