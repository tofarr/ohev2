"""HTTP routes for the api_key feature.

Follows the uniform REST surface (AGENTS.md §3): GET /api-keys (paginated),
POST /api-keys, GET/PATCH/DELETE /api-keys/{id}. Handlers validate, call the
service, and serialize — no business logic here. Every endpoint is guarded by
the centralized permission checker (AGENTS.md §9); the returned
:class:`SearchFilter` is passed into the service constructor so search/update/
delete SQL and create payloads are scoped to the principal.

The single-item create returns :class:`ApiKeyCreated`, which carries the
one-time JWE token secret. Batch creates return ``ApiKeyRead`` (no secret) per
AGENTS.md §3.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.api_key.api_key_schemas import (
    ApiKeyBatchWriteRequest,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRead,
    ApiKeySearchFilter,
    ApiKeySearchResult,
    ApiKeyUpdate,
)
from openhands.ev2.api_key.api_key_service import (
    ApiKeyNotFoundError,
    ApiKeyPermissionScopeError,
    ApiKeyService,
    BatchPermissionDeniedError,
)
from openhands.ev2.auth.auth_dependencies import (
    UserId,
    depends_permissions,
    depends_permissions_or_none,
)
from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=ApiKeySearchResult)
async def search_api_keys(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.SEARCH))
    ],
    # See search_users: bare `Depends()` lets FastAPI explode the filter model's
    # fields as query params.
    search_filter: ApiKeySearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ApiKeySearchResult:
    service = ApiKeyService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    keys, next_cursor = await service.search_api_keys(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return ApiKeySearchResult(
        items=[ApiKeyRead.model_validate(k) for k in keys],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_api_keys(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.SEARCH))
    ],
    # Declared before `/{api_key_id}` so the static path matches ahead of the
    # UUID path param.
    search_filter: ApiKeySearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = ApiKeyService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    payload: ApiKeyCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.CREATE))
    ],
) -> ApiKeyCreated:
    if user_id is None:
        # The CREATE permission dependency already denies anonymous principals
        # (no roles); this guard is defense-in-depth for the type system.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create an API key anonymously.",
        )
    service = ApiKeyService(session, perm_filter)
    try:
        token, api_key = await service.create(payload, user_id=user_id)
    except ApiKeyPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    read = ApiKeyRead.model_validate(api_key)
    return ApiKeyCreated(**read.model_dump(), token=token)


@router.get(
    "/batch",
    response_model=BatchReadResult[ApiKeyRead],
)
async def get_api_keys_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.READ))],
    # Declared before `/{api_key_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids`
    # param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[ApiKeyRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = ApiKeyService(session, perm_filter)
    keys = await service.get_many(ids)
    return BatchReadResult(
        items=[ApiKeyRead.model_validate(k) if k is not None else None for k in keys],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[ApiKeyRead],
)
async def write_api_keys_batch(
    payload: ApiKeyBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. The service denies per operation when its action
    # has no grant. Declared before `/{api_key_id}` so the static `/batch`
    # path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[ApiKey] | None, Depends(depends_permissions_or_none(ApiKey, Action.CREATE))
    ],
    update_filter: Annotated[
        SearchFilter[ApiKey] | None, Depends(depends_permissions_or_none(ApiKey, Action.UPDATE))
    ],
    delete_filter: Annotated[
        SearchFilter[ApiKey] | None, Depends(depends_permissions_or_none(ApiKey, Action.DELETE))
    ],
) -> BatchWriteResult[ApiKeyRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create an API key anonymously.",
        )
    service = ApiKeyService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, user_id=user_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except ApiKeyPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key falls outside your create scope: {exc}",
        ) from exc
    except ApiKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[ApiKeyRead.model_validate(k) if k is not None else None for k in results],
    )


@router.get("/{api_key_id}", response_model=ApiKeyRead)
async def get_api_key(
    api_key_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.READ))],
) -> ApiKeyRead:
    service = ApiKeyService(session, perm_filter)
    try:
        api_key = await service.get(api_key_id)
    except ApiKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {exc}",
        ) from exc
    return ApiKeyRead.model_validate(api_key)


@router.patch("/{api_key_id}", response_model=ApiKeyRead)
async def update_api_key(
    api_key_id: uuid.UUID,
    payload: ApiKeyUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.UPDATE))
    ],
) -> ApiKeyRead:
    service = ApiKeyService(session, perm_filter)
    try:
        api_key = await service.update(api_key_id, payload)
    except ApiKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {exc}",
        ) from exc
    await session.commit()
    return ApiKeyRead.model_validate(api_key)


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    api_key_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[ApiKey], Depends(depends_permissions(ApiKey, Action.DELETE))
    ],
) -> None:
    service = ApiKeyService(session, perm_filter)
    try:
        await service.delete(api_key_id)
    except ApiKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {exc}",
        ) from exc
    await session.commit()
