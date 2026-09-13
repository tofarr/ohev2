"""HTTP routes for the ``/secret-values`` reveal projection.

Read-only surface that returns decrypted plaintext, gated by a **single** USE
permission on the parent :class:`SecretProvider` (AGENTS.md §12). The secret
id in the path and batch reads is the composite ``{provider_id}/{internal_id}``
string (:class:`SecretValue.split_id`). Search pages by provider via
``GET /secret-values?provider_id=...``.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_schemas import SecretValueRead, SecretValueSearchResult
from openhands.ev2.secret.secret_value import SecretValue
from openhands.ev2.secret.secret_value_service import (
    SecretValueNotFoundError,
    SecretValueSession,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/secret-values", tags=["secret-values"])


def _to_read(value: SecretValue) -> SecretValueRead:
    return SecretValueRead(
        id=value.id,
        provider_id=value.provider_id,
        internal_id=value.internal_id,
        name=value.name,
        value=value.value,
        valid_at=value.valid_at,
        expires_at=value.expires_at,
    )


@router.get("", response_model=SecretValueSearchResult)
async def search_secret_values(
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    provider_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.USE)),
    ],
    provider_id: Annotated[uuid.UUID, Query(description="Provider to page secrets from.")],
    cursor: Annotated[str | None, Query(description="Opaque provider cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SecretValueSearchResult:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SecretValueSession(session)
    try:
        values, next_cursor = await service.search(
            provider_id,
            provider_filter,
            limit=limit,
            cursor=cursor,
        )
    except SecretValueNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return SecretValueSearchResult(
        items=[_to_read(v) for v in values], next_cursor=next_cursor, limit=limit
    )


@router.get(
    "/batch",
    response_model=BatchReadResult[SecretValueRead],
)
async def get_secret_values_batch(
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    provider_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.USE)),
    ],
    # Declared before `/{composite_id}` so the static `/batch` path matches
    # ahead of the composite-id path param.
    ids: Annotated[list[str], Query(default_factory=list)],
) -> BatchReadResult[SecretValueRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SecretValueSession(session)
    values = await service.get_many(ids, provider_filter)
    return BatchReadResult(items=[_to_read(v) if v is not None else None for v in values])


@router.get("/{composite_id:path}", response_model=SecretValueRead)
async def get_secret_value(
    composite_id: str,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    provider_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.USE)),
    ],
) -> SecretValueRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SecretValueSession(session)
    try:
        value = await service.get(composite_id, provider_filter)
    except SecretValueNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret value not found: {exc}",
        ) from exc
    return _to_read(value)
