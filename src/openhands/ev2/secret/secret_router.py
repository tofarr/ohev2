"""HTTP routes for the secret feature.

Follows the uniform REST surface (AGENTS.md §3): GET /secrets (paginated),
POST /secrets, GET/PATCH/DELETE /secrets/{id}, plus batch read/write.
Handlers validate, call the service, and serialize — no business logic here.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9)
over the ``secret`` resource; for the :class:`SecretAccess` policy the
read/update/delete filter is a :class:`SecretAccessFilter` keyed on the
matching ``role_secret_permissions`` flag, so a principal sees only the secrets one of
their roles has been granted.
"""

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
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.secret_schemas import (
    SecretBatchWriteRequest,
    SecretCreate,
    SecretRead,
    SecretSearchFilter,
    SecretSearchResult,
    SecretUpdate,
)
from openhands.ev2.secret.secret_service import (
    BatchPermissionDeniedError,
    SecretCodeConflictError,
    SecretNotFoundError,
    SecretPermissionScopeError,
    SecretService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/secrets", tags=["secrets"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=SecretSearchResult)
async def search_secrets(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.SEARCH))
    ],
    search_filter: SecretSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SecretSearchResult:
    service = SecretService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    secrets, next_cursor = await service.search_secrets(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SecretSearchResult(
        items=[service.to_read(s) for s in secrets],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_secrets(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.SEARCH))
    ],
    search_filter: SecretSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = SecretService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=SecretRead, status_code=status.HTTP_201_CREATED)
async def create_secret(
    payload: SecretCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.CREATE))
    ],
) -> SecretRead:
    if user_id is None:
        # The CREATE permission dependency already denies anonymous principals
        # (no roles); this guard is defense-in-depth for the type system.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create a secret anonymously.",
        )
    service = SecretService(session, perm_filter)
    try:
        secret = await service.create(payload, user_id=user_id)
    except SecretPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Secret falls outside your create scope: {exc}",
        ) from exc
    except SecretCodeConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Secret with code already exists: {exc}",
        ) from exc
    await session.commit()
    return service.to_read(secret)


@router.get(
    "/batch",
    response_model=BatchReadResult[SecretRead],
)
async def get_secrets_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Secret], Depends(depends_permissions(Secret, Action.READ))],
    # Declared before `/{secret_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids`
    # param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SecretRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SecretService(session, perm_filter)
    secrets = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(s) if s is not None else None for s in secrets],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[SecretRead],
)
async def write_secrets_batch(
    payload: SecretBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    create_filter: Annotated[
        SearchFilter[Secret] | None, Depends(depends_permissions_or_none(Secret, Action.CREATE))
    ],
    update_filter: Annotated[
        SearchFilter[Secret] | None, Depends(depends_permissions_or_none(Secret, Action.UPDATE))
    ],
    delete_filter: Annotated[
        SearchFilter[Secret] | None, Depends(depends_permissions_or_none(Secret, Action.DELETE))
    ],
) -> BatchWriteResult[SecretRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create a secret anonymously.",
        )
    service = SecretService(session)
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
    except SecretPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Secret falls outside your create scope: {exc}",
        ) from exc
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret not found: {exc}",
        ) from exc
    except SecretCodeConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Secret with code already exists: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(s) if s is not None else None for s in results],
    )


@router.get("/{secret_id}", response_model=SecretRead)
async def get_secret(
    secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Secret], Depends(depends_permissions(Secret, Action.READ))],
) -> SecretRead:
    service = SecretService(session, perm_filter)
    try:
        secret = await service.get(secret_id)
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret not found: {exc}",
        ) from exc
    return service.to_read(secret)


@router.patch("/{secret_id}", response_model=SecretRead)
async def update_secret(
    secret_id: uuid.UUID,
    payload: SecretUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.UPDATE))
    ],
) -> SecretRead:
    service = SecretService(session, perm_filter)
    try:
        secret = await service.update(secret_id, payload)
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret not found: {exc}",
        ) from exc
    except SecretCodeConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Secret with code already exists: {exc}",
        ) from exc
    await session.commit()
    return service.to_read(secret)


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.DELETE))
    ],
) -> None:
    service = SecretService(session, perm_filter)
    try:
        await service.delete(secret_id)
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret not found: {exc}",
        ) from exc
    await session.commit()
