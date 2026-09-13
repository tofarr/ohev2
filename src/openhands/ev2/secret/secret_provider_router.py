"""HTTP routes for the governed ``/secret-providers`` resource.

Uniform REST surface (AGENTS.md §3): full CRUD with batch read/write and
cursor pagination. ``data`` values are stored encrypted at rest and masked in
responses; a caller that explicitly passes the §13 ``expose_secrets`` context
flag (e.g. an admin tool that needs to round-trip plaintext) sees plaintext.
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
from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_provider_service import (
    BatchPermissionDeniedError,
    SecretProviderNotFoundError,
    SecretProviderPermissionScopeError,
    SecretProviderService,
)
from openhands.ev2.secret.secret_schemas import (
    SecretProviderBatchWriteRequest,
    SecretProviderCreate,
    SecretProviderRead,
    SecretProviderSearchFilter,
    SecretProviderSearchResult,
    SecretProviderUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/secret-providers", tags=["secret-providers"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=SecretProviderSearchResult)
async def search_secret_providers(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.SEARCH)),
    ],
    search_filter: SecretProviderSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SecretProviderSearchResult:
    service = SecretProviderService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    providers, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SecretProviderSearchResult(
        items=[service.to_read(p) for p in providers],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_secret_providers(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.READ)),
    ],
    search_filter: SecretProviderSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = SecretProviderService(session, perm_filter)
    return CountResult(count=await service.count(search_filter))


@router.post("", response_model=SecretProviderRead, status_code=status.HTTP_201_CREATED)
async def create_secret_provider(
    payload: SecretProviderCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.CREATE)),
    ],
) -> SecretProviderRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SecretProviderService(session, perm_filter)
    try:
        provider = await service.create(payload, creator_id=user_id)
    except SecretProviderPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(provider)


@router.get(
    "/batch",
    response_model=BatchReadResult[SecretProviderRead],
)
async def get_secret_providers_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SecretProviderRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = SecretProviderService(session, perm_filter)
    providers = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(p) if p is not None else None for p in providers],
    )


async def _apply_batch(
    service: SecretProviderService,
    payload: SecretProviderBatchWriteRequest,
    perm_filters: dict[Action, SearchFilter[SecretProvider] | None],
    creator_id: uuid.UUID,
) -> list[SecretProvider | None]:
    """Apply a batch write, mapping service errors to HTTP exceptions."""
    # One named except per error type keeps the status mapping explicit.
    # pylint: disable=too-complex
    try:
        return await service.apply_batch(payload.operations, perm_filters, creator_id=creator_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except SecretProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except SecretProviderPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post(
    "/batch",
    response_model=BatchWriteResult[SecretProviderRead],
)
async def write_secret_providers_batch(
    payload: SecretProviderBatchWriteRequest,
    session: SessionDep,
    create_filter: Annotated[
        SearchFilter[SecretProvider] | None,
        Depends(depends_permissions_or_none(SecretProvider, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[SecretProvider] | None,
        Depends(depends_permissions_or_none(SecretProvider, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[SecretProvider] | None,
        Depends(depends_permissions_or_none(SecretProvider, Action.DELETE)),
    ],
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
) -> BatchWriteResult[SecretProviderRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = SecretProviderService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    results = await _apply_batch(service, payload, perm_filters, user_id)
    await session.commit()
    return BatchWriteResult(
        items=[service.to_read(p) if p is not None else None for p in results],
    )


@router.get("/{provider_id}", response_model=SecretProviderRead)
async def get_secret_provider(
    provider_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.READ)),
    ],
) -> SecretProviderRead:
    service = SecretProviderService(session, perm_filter)
    try:
        provider = await service.get(provider_id)
    except SecretProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return service.to_read(provider)


@router.patch("/{provider_id}", response_model=SecretProviderRead)
async def update_secret_provider(
    provider_id: uuid.UUID,
    payload: SecretProviderUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.UPDATE)),
    ],
) -> SecretProviderRead:
    service = SecretProviderService(session, perm_filter)
    try:
        provider = await service.update(provider_id, payload)
    except SecretProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(provider)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret_provider(
    provider_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[SecretProvider],
        Depends(depends_permissions(SecretProvider, Action.DELETE)),
    ],
) -> None:
    service = SecretProviderService(session, perm_filter)
    try:
        await service.delete(provider_id)
    except SecretProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    await session.commit()
