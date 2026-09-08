"""HTTP routes for the ``/secret-values`` reveal projection.

Read-only surface that returns decrypted plaintext. Three endpoints, all
requiring *both* read access to the secret (``secret_permission`` READ via
:func:`depends_permissions`) and the value-reveal permission
(``secret_value_permission`` via :func:`depends_secret_value_permission`).
A secret is revealed only when both admit it (defense in depth, AGENTS.md §12).

Follows the uniform REST surface (AGENTS.md §3): plural lowercase noun,
standard verbs, ProblemDetail errors, no ``/search`` or ``/list`` paths.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_secret_value_permission,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.secret.secret_models import Secret
from openhands.ev2.secret.secret_schemas import (
    SecretSearchFilter,
    SecretValueRead,
    SecretValueSearchResult,
)
from openhands.ev2.secret.secret_service import (
    SecretValueNotFoundError,
    SecretValueService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/secret-values", tags=["secret-values"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _service(
    session: SessionDep,
    read_filter: SearchFilter[Secret],
    value_filter: SearchFilter[Secret],
) -> SecretValueService:
    return SecretValueService(session, read_filter, value_filter)


@router.get("", response_model=SecretValueSearchResult)
async def search_secret_values(
    session: SessionDep,
    read_filter: Annotated[
        SearchFilter[Secret], Depends(depends_permissions(Secret, Action.SEARCH))
    ],
    value_filter: Annotated[SearchFilter[Secret], Depends(depends_secret_value_permission())],
    search_filter: SecretSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> SecretValueSearchResult:
    service = _service(session, read_filter, value_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    reads, next_cursor = await service.search_values(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return SecretValueSearchResult(
        items=reads,
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get(
    "/batch",
    response_model=BatchReadResult[SecretValueRead],
)
async def get_secret_values_batch(
    session: SessionDep,
    read_filter: Annotated[SearchFilter[Secret], Depends(depends_permissions(Secret, Action.READ))],
    value_filter: Annotated[SearchFilter[Secret], Depends(depends_secret_value_permission())],
    # Declared before `/{secret_id}` so the static `/batch` path matches ahead
    # of the UUID path param. Default to an empty list so an omitted `ids`
    # param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[SecretValueRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = _service(session, read_filter, value_filter)
    reads = await service.get_many(ids)
    return BatchReadResult(items=reads)


@router.get("/{secret_id}", response_model=SecretValueRead)
async def get_secret_value(
    secret_id: uuid.UUID,
    session: SessionDep,
    read_filter: Annotated[SearchFilter[Secret], Depends(depends_permissions(Secret, Action.READ))],
    value_filter: Annotated[SearchFilter[Secret], Depends(depends_secret_value_permission())],
) -> SecretValueRead:
    service = _service(session, read_filter, value_filter)
    try:
        return await service.get(secret_id)
    except SecretValueNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret value not found: {exc}",
        ) from exc
