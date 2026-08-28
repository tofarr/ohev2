"""HTTP routes for the CORS allow-list feature.

Uniform REST surface (AGENTS.md §3). The collection is ``/cors-origins`` with
cursor pagination; create is ``POST``, remove is ``DELETE /{id}``. Every
endpoint is guarded by the centralized permission checker (AGENTS.md §9) over
the ``cors_origin`` resource type. Origins are immutable; there is no update.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth2.auth2_dependencies import depends_permissions
from openhands.ev2.cors.cors_models import AllowedOrigin
from openhands.ev2.cors.cors_schemas import (
    AllowedOriginCreate,
    AllowedOriginRead,
    AllowedOriginSearchResult,
)
from openhands.ev2.cors.cors_service import (
    AllowedOriginConflictError,
    AllowedOriginNotFoundError,
    CorsService,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/cors-origins", tags=["cors-origins"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


async def _to_read(origin: Any) -> AllowedOriginRead:
    return AllowedOriginRead(
        id=origin.id,
        origin=origin.origin,
        created_at=origin.created_at,
    )


@router.get("", response_model=AllowedOriginSearchResult)
async def search_cors_origins(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(AllowedOrigin, Action.SEARCH))
    ],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> AllowedOriginSearchResult:
    _ = perm_filter  # cors origins are global; the filter only gates access.
    service = CorsService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    origins, next_cursor = await service.list_allowed_origins(
        cursor=cursor_uuid,
        limit=limit,
    )
    return AllowedOriginSearchResult(
        items=[await _to_read(o) for o in origins],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post("", response_model=AllowedOriginRead, status_code=status.HTTP_201_CREATED)
async def create_cors_origin(
    payload: AllowedOriginCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(AllowedOrigin, Action.CREATE))
    ],
) -> AllowedOriginRead:
    _ = perm_filter
    service = CorsService(session)
    try:
        origin = await service.create_allowed_origin(payload.origin)
    except AllowedOriginConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Origin already registered: {exc}",
        ) from exc
    await session.commit()
    return await _to_read(origin)


@router.delete("/{origin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cors_origin(
    origin_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(AllowedOrigin, Action.DELETE))
    ],
) -> None:
    _ = perm_filter
    service = CorsService(session)
    try:
        await service.delete_allowed_origin(origin_id)
    except AllowedOriginNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Origin not found: {exc}",
        ) from exc
    await session.commit()
