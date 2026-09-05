"""HTTP routes for per-user secret permissions.

Uniform REST surface (AGENTS.md §3): the collection is
``/user-secret-permissions`` with cursor pagination; create is ``POST``, update
is ``PATCH`` (the link is mutable — toggle the read/update/delete flags),
retrieve is ``GET``, remove is ``DELETE``, plus batch read/write.

Authorization models the link as a sub-resource of ``user``: managing a user's
secret grants requires the ``UPDATE`` action on the ``user`` resource, while
listing and retrieving grants requires ``READ`` on the ``user`` resource.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from openhands.ev2.auth.auth_dependencies import depends_permissions
from openhands.ev2.db import SessionDep
from openhands.ev2.secret.user_secret_permission_schemas import (
    UserSecretPermissionBatchWriteRequest,
    UserSecretPermissionCreate,
    UserSecretPermissionRead,
    UserSecretPermissionSearchFilter,
    UserSecretPermissionSearchResult,
    UserSecretPermissionUpdate,
)
from openhands.ev2.secret.user_secret_permission_service import (
    UserSecretPermissionConflictError,
    UserSecretPermissionNotFoundError,
    UserSecretPermissionOrphanError,
    UserSecretPermissionService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/user-secret-permissions", tags=["user-secret-permissions"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


def _to_read(link: Any) -> UserSecretPermissionRead:
    return UserSecretPermissionRead.model_validate(link)


@router.get("", response_model=UserSecretPermissionSearchResult)
async def search_user_secret_permissions(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.READ))],
    search_filter: UserSecretPermissionSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserSecretPermissionSearchResult:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_user_secret_permissions(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return UserSecretPermissionSearchResult(
        items=[_to_read(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_user_secret_permissions(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.READ))],
    search_filter: UserSecretPermissionSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=UserSecretPermissionRead, status_code=status.HTTP_201_CREATED)
async def create_user_secret_permission(
    payload: UserSecretPermissionCreate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.UPDATE))],
) -> UserSecretPermissionRead:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    try:
        link = await service.create(
            user_id=payload.user_id,
            secret_id=payload.secret_id,
            read_enabled=payload.read_enabled,
            update_enabled=payload.update_enabled,
            delete_enabled=payload.delete_enabled,
        )
    except UserSecretPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except UserSecretPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced secret or user not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.get(
    "/batch",
    response_model=BatchReadResult[UserSecretPermissionRead],
)
async def get_user_secret_permissions_batch(
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.READ))],
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[UserSecretPermissionRead]:
    _ = perm_filter
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = UserSecretPermissionService(session)
    links = await service.get_many(ids)
    return BatchReadResult(items=[_to_read(link) if link is not None else None for link in links])


@router.post(
    "/batch",
    response_model=BatchWriteResult[UserSecretPermissionRead],
)
async def write_user_secret_permissions_batch(
    payload: UserSecretPermissionBatchWriteRequest,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.UPDATE))],
) -> BatchWriteResult[UserSecretPermissionRead]:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    try:
        results = await service.apply_batch(payload.operations)
    except UserSecretPermissionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Grant already exists: {exc}",
        ) from exc
    except UserSecretPermissionOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced secret or user not found: {exc}",
        ) from exc
    except UserSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[_to_read(link) if link is not None else None for link in results],
    )


@router.get("/{user_secret_permission_id}", response_model=UserSecretPermissionRead)
async def get_user_secret_permission(
    user_secret_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.READ))],
) -> UserSecretPermissionRead:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    try:
        link = await service.get(user_secret_permission_id)
    except UserSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    return _to_read(link)


@router.patch("/{user_secret_permission_id}", response_model=UserSecretPermissionRead)
async def update_user_secret_permission(
    user_secret_permission_id: uuid.UUID,
    payload: UserSecretPermissionUpdate,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.UPDATE))],
) -> UserSecretPermissionRead:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    try:
        link = await service.update(user_secret_permission_id, payload)
    except UserSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
    return _to_read(link)


@router.delete("/{user_secret_permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_secret_permission(
    user_secret_permission_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[SearchFilter[Any], Depends(depends_permissions(User, Action.UPDATE))],
) -> None:
    _ = perm_filter
    service = UserSecretPermissionService(session)
    try:
        await service.delete(user_secret_permission_id)
    except UserSecretPermissionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Grant not found: {exc}",
        ) from exc
    await session.commit()
