"""HTTP routes for the conversation template feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/conversation-templates``
with cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, remove is ``DELETE``; batch read + batch write are also provided.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9)
over the ``conversation_template`` resource; the returned :class:`SearchFilter`
scopes the service SQL to rows the principal may see.
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
from openhands.ev2.conversation_template.conversation_template_models import (
    ConversationTemplate,
)
from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateBatchWriteRequest,
    ConversationTemplateCreate,
    ConversationTemplateRead,
    ConversationTemplateSearchFilter,
    ConversationTemplateSearchResult,
    ConversationTemplateUpdate,
)
from openhands.ev2.conversation_template.conversation_template_service import (
    BatchPermissionDeniedError,
    ConversationTemplateNotFoundError,
    ConversationTemplatePermissionScopeError,
    ConversationTemplateService,
    ReferencedEntityNotFoundError,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/conversation-templates", tags=["conversation-templates"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=ConversationTemplateSearchResult)
async def search_conversation_templates(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.SEARCH)),
    ],
    search_filter: ConversationTemplateSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ConversationTemplateSearchResult:
    service = ConversationTemplateService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    rows, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return ConversationTemplateSearchResult(
        items=[ConversationTemplateRead.model_validate(r) for r in rows],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_conversation_templates(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.SEARCH)),
    ],
    search_filter: ConversationTemplateSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = ConversationTemplateService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=ConversationTemplateRead, status_code=status.HTTP_201_CREATED)
async def create_conversation_template(
    payload: ConversationTemplateCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.CREATE)),
    ],
) -> ConversationTemplateRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = ConversationTemplateService(session, perm_filter)
    try:
        template = await service.create(payload, creator_id=user_id)
    except ConversationTemplatePermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation template falls outside your create scope: {exc}",
        ) from exc
    except ReferencedEntityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced entity not found: {exc}",
        ) from exc
    await session.commit()
    return ConversationTemplateRead.model_validate(template)


@router.get("/batch", response_model=BatchReadResult[ConversationTemplateRead])
async def get_conversation_templates_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.READ)),
    ],
    # Declared before `/{template_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[ConversationTemplateRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = ConversationTemplateService(session, perm_filter)
    templates = await service.get_many(ids)
    return BatchReadResult(
        items=[
            ConversationTemplateRead.model_validate(t) if t is not None else None for t in templates
        ],
    )


@router.post("/batch", response_model=BatchWriteResult[ConversationTemplateRead])
async def write_conversation_templates_batch(
    payload: ConversationTemplateBatchWriteRequest,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{template_id}` so the static
    # `/batch` path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[ConversationTemplate] | None,
        Depends(depends_permissions_or_none(ConversationTemplate, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[ConversationTemplate] | None,
        Depends(depends_permissions_or_none(ConversationTemplate, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[ConversationTemplate] | None,
        Depends(depends_permissions_or_none(ConversationTemplate, Action.DELETE)),
    ],
) -> BatchWriteResult[ConversationTemplateRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = ConversationTemplateService(session)
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
    except ConversationTemplatePermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Conversation template falls outside your create scope: {exc}",
        ) from exc
    except ConversationTemplateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation template not found: {exc}",
        ) from exc
    except ReferencedEntityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced entity not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[
            ConversationTemplateRead.model_validate(t) if t is not None else None for t in results
        ],
    )


@router.get("/{template_id}", response_model=ConversationTemplateRead)
async def get_conversation_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.READ)),
    ],
) -> ConversationTemplateRead:
    service = ConversationTemplateService(session, perm_filter)
    try:
        template = await service.get(template_id)
    except ConversationTemplateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation template not found: {exc}",
        ) from exc
    return ConversationTemplateRead.model_validate(template)


@router.patch("/{template_id}", response_model=ConversationTemplateRead)
async def update_conversation_template(
    template_id: uuid.UUID,
    payload: ConversationTemplateUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.UPDATE)),
    ],
) -> ConversationTemplateRead:
    service = ConversationTemplateService(session, perm_filter)
    try:
        template = await service.update(template_id, payload)
    except ConversationTemplateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation template not found: {exc}",
        ) from exc
    except ReferencedEntityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced entity not found: {exc}",
        ) from exc
    await session.commit()
    return ConversationTemplateRead.model_validate(template)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation_template(
    template_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ConversationTemplate],
        Depends(depends_permissions(ConversationTemplate, Action.DELETE)),
    ],
) -> None:
    service = ConversationTemplateService(session, perm_filter)
    try:
        await service.delete(template_id)
    except ConversationTemplateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation template not found: {exc}",
        ) from exc
    await session.commit()
