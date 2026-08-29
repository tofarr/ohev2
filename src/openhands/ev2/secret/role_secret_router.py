"""HTTP routes for the role-secret grant feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/role-secrets`` with
cursor pagination; create is ``POST``, update is ``PATCH`` (the link is
mutable — toggle the read/update/delete flags), retrieve is ``GET``, remove
is ``DELETE``, plus batch read/write.

Authorization models the link as a sub-resource of ``role`` (mirroring
``/user-roles``): managing a role's secret grants requires the ``UPDATE``
action on the ``role`` resource, while listing and retrieving grants requires
``READ`` on the ``role`` resource. Every endpoint is guarded by the
centralized permission checker (AGENTS.md §9).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.role.role_models import Role
from openhands.ev2.secret.role_secret_schemas import (
    RoleSecretBatchWriteRequest,
    RoleSecretCreate,
    RoleSecretRead,
    RoleSecretSearchFilter,
    RoleSecretSearchResult,
    RoleSecretUpdate,
)
from openhands.ev2.secret.role_secret_service import (
    RoleSecretConflictError,
    RoleSecretNotFoundError,
    RoleSecretOrphanError,
    RoleSecretService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/role-secrets", tags=["role-secrets"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _to_read(link: Any) -> RoleSecretRead:
    return RoleSecretRead.model_validate(link)


@router.get("", response_model=RoleSecretSearchResult)
async def search_role_secrets(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleSecretSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> RoleSecretSearchResult:
    _ = perm_filter  # grants are global; the filter only gates access.
    service = RoleSecretService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_role_secrets(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return RoleSecretSearchResult(
        items=[_to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_role_secrets(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    search_filter: RoleSecretSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = RoleSecretService(session)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=RoleSecretRead, status_code=status.HTTP_201_CREATED)
async def create_role_secret(
    payload: RoleSecretCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleSecretRead:
    _ = perm_filter
    service = RoleSecretService(session)
    try:
        link = await service.create(
            role_id=payload.role_id,
            secret_id=payload.secret_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except RoleSecretConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleSecretOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or secret not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.get(
    "/batch",
    response_model=BatchReadResult[RoleSecretRead],
)
async def get_role_secrets_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
    # Declared before `/{role_secret_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[RoleSecretRead]:
    _ = perm_filter
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = RoleSecretService(session)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[_to_read(link) if link is not None else None for link in links],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[RoleSecretRead],
)
async def write_role_secrets_batch(
    payload: RoleSecretBatchWriteRequest,
    session: SessionDep,
    # Managing grants requires UPDATE on the role resource, mirroring the
    # single-item create/update/delete endpoints.
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> BatchWriteResult[RoleSecretRead]:
    _ = perm_filter
    service = RoleSecretService(session)
    try:
        results = await service.apply_batch(payload.operations)
    except RoleSecretConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except RoleSecretOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced role or secret not found: {exc}",
        ) from exc
    except RoleSecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[_to_read(link) if link is not None else None for link in results],
    )


@router.get("/{role_secret_id}", response_model=RoleSecretRead)
async def get_role_secret(
    role_secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.READ))],
) -> RoleSecretRead:
    _ = perm_filter
    service = RoleSecretService(session)
    try:
        link = await service.get(role_secret_id)
    except RoleSecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    return _to_read(link)


@router.patch("/{role_secret_id}", response_model=RoleSecretRead)
async def update_role_secret(
    role_secret_id: uuid.UUID,
    payload: RoleSecretUpdate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> RoleSecretRead:
    _ = perm_filter
    service = RoleSecretService(session)
    try:
        link = await service.update(role_secret_id, payload)
    except RoleSecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.delete("/{role_secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role_secret(
    role_secret_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(Role, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = RoleSecretService(session)
    try:
        await service.delete(role_secret_id)
    except RoleSecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
