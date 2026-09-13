"""HTTP routes for the ``/static-secrets`` resource.

Uniform REST surface (AGENTS.md §3): full CRUD with batch read/write and
cursor pagination over :class:`StaticSecret`. The ``value`` is never returned
by this surface — plaintext is revealed only through ``/secret-values`` (whose
single gate is USE on the parent static provider).
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
from openhands.ev2.secret.secret_models import StaticSecret
from openhands.ev2.secret.secret_schemas import (
    StaticSecretBatchWriteRequest,
    StaticSecretCreate,
    StaticSecretRead,
    StaticSecretSearchFilter,
    StaticSecretSearchResult,
    StaticSecretUpdate,
)
from openhands.ev2.secret.static_secret_service import (
    BatchPermissionDeniedError,
    StaticSecretNameConflictError,
    StaticSecretNotFoundError,
    StaticSecretPermissionScopeError,
    StaticSecretService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/static-secrets", tags=["static-secrets"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=StaticSecretSearchResult)
async def search_static_secrets(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.SEARCH)),
    ],
    search_filter: StaticSecretSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> StaticSecretSearchResult:
    service = StaticSecretService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    secrets, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return StaticSecretSearchResult(
        items=[service.to_read(s) for s in secrets],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_static_secrets(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.READ)),
    ],
    search_filter: StaticSecretSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = StaticSecretService(session, perm_filter)
    return CountResult(count=await service.count(search_filter))


@router.post("", response_model=StaticSecretRead, status_code=status.HTTP_201_CREATED)
async def create_static_secret(
    payload: StaticSecretCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.CREATE)),
    ],
) -> StaticSecretRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = StaticSecretService(session, perm_filter)
    try:
        secret = await service.create(payload, creator_id=user_id)
    except StaticSecretPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except StaticSecretNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(secret)


@router.get(
    "/batch",
    response_model=BatchReadResult[StaticSecretRead],
)
async def get_static_secrets_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[StaticSecretRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = StaticSecretService(session, perm_filter)
    secrets = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(s) if s is not None else None for s in secrets],
    )


async def _apply_batch(
    service: StaticSecretService,
    payload: StaticSecretBatchWriteRequest,
    perm_filters: dict[Action, SearchFilter[StaticSecret] | None],
    creator_id: uuid.UUID,
) -> list[StaticSecret | None]:
    """Apply a batch write, mapping service errors to HTTP exceptions."""
    # One named except per error type keeps the status mapping explicit.
    # pylint: disable=too-complex
    try:
        return await service.apply_batch(payload.operations, perm_filters, creator_id=creator_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except StaticSecretNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StaticSecretNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except StaticSecretPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post(
    "/batch",
    response_model=BatchWriteResult[StaticSecretRead],
)
async def write_static_secrets_batch(
    payload: StaticSecretBatchWriteRequest,
    session: SessionDep,
    create_filter: Annotated[
        SearchFilter[StaticSecret] | None,
        Depends(depends_permissions_or_none(StaticSecret, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[StaticSecret] | None,
        Depends(depends_permissions_or_none(StaticSecret, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[StaticSecret] | None,
        Depends(depends_permissions_or_none(StaticSecret, Action.DELETE)),
    ],
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
) -> BatchWriteResult[StaticSecretRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = StaticSecretService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    results = await _apply_batch(service, payload, perm_filters, user_id)
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(s) if s is not None else None for s in results],
    )


@router.get("/{secret_id}", response_model=StaticSecretRead)
async def get_static_secret(
    secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.READ)),
    ],
) -> StaticSecretRead:
    service = StaticSecretService(session, perm_filter)
    try:
        secret = await service.get(secret_id)
    except StaticSecretNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return service.to_read(secret)


@router.patch("/{secret_id}", response_model=StaticSecretRead)
async def update_static_secret(
    secret_id: uuid.UUID,
    payload: StaticSecretUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.UPDATE)),
    ],
) -> StaticSecretRead:
    service = StaticSecretService(session, perm_filter)
    try:
        secret = await service.update(secret_id, payload)
    except StaticSecretNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except StaticSecretNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(secret)


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_static_secret(
    secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[StaticSecret],
        Depends(depends_permissions(StaticSecret, Action.DELETE)),
    ],
) -> None:
    service = StaticSecretService(session, perm_filter)
    try:
        await service.delete(secret_id)
    except StaticSecretNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    await session.commit()
