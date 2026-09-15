"""HTTP routes for the governed ``/oauth/providers`` resource.

Uniform REST surface (AGENTS.md §3): full CRUD with batch read/write and
cursor pagination. ``client_secret`` is masked in responses (§13).
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
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_provider_schemas import (
    OAuthProviderBatchWriteRequest,
    OAuthProviderCreate,
    OAuthProviderRead,
    OAuthProviderSearchFilter,
    OAuthProviderSearchResult,
    OAuthProviderUpdate,
)
from openhands.ev2.oauth.oauth_provider_service import (
    BatchPermissionDeniedError,
    OAuthProviderNameConflictError,
    OAuthProviderNotFoundError,
    OAuthProviderPermissionScopeError,
    OAuthProviderService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/oauth/providers", tags=["oauth-providers"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get("", response_model=OAuthProviderSearchResult)
async def search_oauth_providers(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.SEARCH)),
    ],
    search_filter: OAuthProviderSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OAuthProviderSearchResult:
    service = OAuthProviderService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    providers, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return OAuthProviderSearchResult(
        items=[service.to_read(p) for p in providers],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_oauth_providers(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.READ)),
    ],
    search_filter: OAuthProviderSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = OAuthProviderService(session, perm_filter)
    return CountResult(count=await service.count(search_filter))


@router.post("", response_model=OAuthProviderRead, status_code=status.HTTP_201_CREATED)
async def create_oauth_provider(
    payload: OAuthProviderCreate,
    session: SessionDep,
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.CREATE)),
    ],
) -> OAuthProviderRead:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = OAuthProviderService(session, perm_filter)
    try:
        provider = await service.create(payload, creator_id=user_id)
    except OAuthProviderNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OAuthProviderPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(provider)


@router.get(
    "/batch",
    response_model=BatchReadResult[OAuthProviderRead],
)
async def get_oauth_providers_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.READ)),
    ],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[OAuthProviderRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = OAuthProviderService(session, perm_filter)
    providers = await service.get_many(ids)
    return BatchReadResult(
        items=[service.to_read(p) if p is not None else None for p in providers],
    )


async def _apply_batch(
    service: OAuthProviderService,
    payload: OAuthProviderBatchWriteRequest,
    perm_filters: dict[Action, SearchFilter[OAuthProvider] | None],
    creator_id: uuid.UUID,
) -> list[OAuthProvider | None]:
    """Apply a batch write, mapping service errors to HTTP exceptions."""
    # pylint: disable=too-complex
    try:
        return await service.apply_batch(payload.operations, perm_filters, creator_id=creator_id)
    except (BatchPermissionDeniedError, OAuthProviderPermissionScopeError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OAuthProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except OAuthProviderNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post(
    "/batch",
    response_model=BatchWriteResult[OAuthProviderRead],
)
async def write_oauth_providers_batch(
    payload: OAuthProviderBatchWriteRequest,
    session: SessionDep,
    create_filter: Annotated[
        SearchFilter[OAuthProvider] | None,
        Depends(depends_permissions_or_none(OAuthProvider, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[OAuthProvider] | None,
        Depends(depends_permissions_or_none(OAuthProvider, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[OAuthProvider] | None,
        Depends(depends_permissions_or_none(OAuthProvider, Action.DELETE)),
    ],
    user_id: Annotated[uuid.UUID | None, Depends(depends_user_id)],
) -> BatchWriteResult[OAuthProviderRead]:
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    service = OAuthProviderService(session)
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


@router.get("/{provider_id}", response_model=OAuthProviderRead)
async def get_oauth_provider(
    provider_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.READ)),
    ],
) -> OAuthProviderRead:
    service = OAuthProviderService(session, perm_filter)
    try:
        provider = await service.get(provider_id)
    except OAuthProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return service.to_read(provider)


@router.patch("/{provider_id}", response_model=OAuthProviderRead)
async def update_oauth_provider(
    provider_id: uuid.UUID,
    payload: OAuthProviderUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.UPDATE)),
    ],
) -> OAuthProviderRead:
    service = OAuthProviderService(session, perm_filter)
    try:
        provider = await service.update(provider_id, payload)
    except OAuthProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except OAuthProviderNameConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await session.commit()
    return service.to_read(provider)


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_oauth_provider(
    provider_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[OAuthProvider],
        Depends(depends_permissions(OAuthProvider, Action.DELETE)),
    ],
) -> None:
    service = OAuthProviderService(session, perm_filter)
    try:
        await service.delete(provider_id)
    except OAuthProviderNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except OAuthProviderPermissionScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await session.commit()
