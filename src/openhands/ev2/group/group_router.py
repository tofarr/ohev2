"""HTTP routes for the group feature.

Uniform REST surface (AGENTS.md §3). Two collections:

* ``/groups`` — full CRUD (GET paginated, POST, GET/{id}, PATCH/{id},
  DELETE/{id}) plus batch read/write and count. ``creator_id`` is the
  authenticated principal, set by the service from ``depends_user_id``.
* ``/group-users`` — immutable membership link rows (GET paginated, POST,
  GET/{id}, DELETE/{id}) plus batch read/write and count; no ``PATCH``.

Handlers validate, call a service, and serialize — no business logic here.
Every endpoint is guarded by the centralized permission checker (AGENTS.md §9);
the returned :class:`SearchFilter` scopes the service SQL to rows the principal
may see. The ``group-users`` link table is guarded by its own
``group_user_permission`` column — managing membership is deliberately not
implied by ``group_permission`` update (AGENTS.md §11.1).
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
from openhands.ev2.group.group_models import Group as GroupModel
from openhands.ev2.group.group_models import GroupUser as GroupUserModel
from openhands.ev2.group.group_schemas import (
    GroupBatchWriteRequest,
    GroupCreate,
    GroupRead,
    GroupSearchFilter,
    GroupSearchResult,
    GroupUpdate,
    GroupUserBatchWriteRequest,
    GroupUserCreate,
    GroupUserRead,
    GroupUserSearchFilter,
    GroupUserSearchResult,
)
from openhands.ev2.group.group_service import (
    BatchPermissionDeniedError,
    GroupNotFoundError,
    GroupPermissionScopeError,
    GroupService,
    GroupUserConflictError,
    GroupUserNotFoundError,
    GroupUserOrphanError,
    GroupUserPermissionScopeError,
    GroupUserService,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.schemas import BatchReadResult, BatchWriteResult, CountResult
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/groups", tags=["groups"])
# Memberships are grouped under the groups tag (AGENTS.md §3) so the OpenAPI
# doc surfaces them under the entity they relate to.
members_router = APIRouter(prefix="/group-users", tags=["groups"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


async def _require_user_id(user_id: UserId) -> uuid.UUID:
    """Return the authenticated principal's id, or 403 if anonymous.

    The CREATE permission dependency already denies anonymous principals (no
    roles); this guard is defense-in-depth for the type system.
    """
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create a group anonymously.",
        )
    return user_id


# ====================================================================== #
# Groups
# ====================================================================== #


@router.get("", response_model=GroupSearchResult)
async def search_groups(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.SEARCH))
    ],
    search_filter: GroupSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> GroupSearchResult:
    service = GroupService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    groups, next_cursor = await service.search(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return GroupSearchResult(
        items=[GroupRead.model_validate(g) for g in groups],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get("/count", response_model=CountResult)
async def count_groups(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.SEARCH))
    ],
    search_filter: GroupSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = GroupService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@router.post("", response_model=GroupRead, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: GroupCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.CREATE))
    ],
) -> GroupRead:
    creator_id = await _require_user_id(user_id)
    service = GroupService(session, perm_filter)
    try:
        group = await service.create(payload, creator_id=creator_id)
    except GroupPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Group falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return GroupRead.model_validate(group)


@router.get(
    "/batch",
    response_model=BatchReadResult[GroupRead],
)
async def get_groups_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.READ))
    ],
    # Declared before `/{group_id}` so the static `/batch` path matches ahead of
    # the UUID path param. Default to an empty list so an omitted `ids` param
    # is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[GroupRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = GroupService(session, perm_filter)
    groups = await service.get_many(ids)
    return BatchReadResult(
        items=[GroupRead.model_validate(g) if g is not None else None for g in groups],
    )


@router.post(
    "/batch",
    response_model=BatchWriteResult[GroupRead],
)
async def write_groups_batch(
    payload: GroupBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    # Resolve a per-action filter without raising so a CUD batch does not 403
    # on an unused action. Declared before `/{group_id}` so the static `/batch`
    # path matches ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[GroupModel] | None,
        Depends(depends_permissions_or_none(GroupModel, Action.CREATE)),
    ],
    update_filter: Annotated[
        SearchFilter[GroupModel] | None,
        Depends(depends_permissions_or_none(GroupModel, Action.UPDATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[GroupModel] | None,
        Depends(depends_permissions_or_none(GroupModel, Action.DELETE)),
    ],
) -> BatchWriteResult[GroupRead]:
    creator_id = await _require_user_id(user_id)
    service = GroupService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.UPDATE: update_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, creator_id=creator_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except GroupPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Group falls outside your create scope: {exc}",
        ) from exc
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[GroupRead.model_validate(g) if g is not None else None for g in results],
    )


@router.get("/{group_id}", response_model=GroupRead)
async def get_group(
    group_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.READ))
    ],
) -> GroupRead:
    service = GroupService(session, perm_filter)
    try:
        group = await service.get(group_id)
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group not found: {exc}",
        ) from exc
    return GroupRead.model_validate(group)


@router.patch("/{group_id}", response_model=GroupRead)
async def update_group(
    group_id: uuid.UUID,
    payload: GroupUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.UPDATE))
    ],
) -> GroupRead:
    service = GroupService(session, perm_filter)
    try:
        group = await service.update(group_id, payload)
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group not found: {exc}",
        ) from exc
    except GroupPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Group falls outside your create scope: {exc}",
        ) from exc
    await session.commit()
    return GroupRead.model_validate(group)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupModel], Depends(depends_permissions(GroupModel, Action.DELETE))
    ],
) -> None:
    service = GroupService(session, perm_filter)
    try:
        await service.delete(group_id)
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group not found: {exc}",
        ) from exc
    await session.commit()


# ====================================================================== #
# Group users (memberships)
# ====================================================================== #


@members_router.get("", response_model=GroupUserSearchResult)
async def search_group_users(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.SEARCH))
    ],
    search_filter: GroupUserSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> GroupUserSearchResult:
    service = GroupUserService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    links, next_cursor = await service.search_group_users(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return GroupUserSearchResult(
        items=[GroupUserRead.model_validate(link) for link in links],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@members_router.get("/count", response_model=CountResult)
async def count_group_users(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.SEARCH))
    ],
    search_filter: GroupUserSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = GroupUserService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


@members_router.post("", response_model=GroupUserRead, status_code=status.HTTP_201_CREATED)
async def create_group_user(
    payload: GroupUserCreate,
    session: SessionDep,
    user_id: UserId,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.CREATE))
    ],
) -> GroupUserRead:
    creator_id = await _require_user_id(user_id)
    service = GroupUserService(session, perm_filter)
    try:
        link = await service.create(payload, creator_id=creator_id)
    except GroupUserPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Membership falls outside your create scope: {exc}",
        ) from exc
    except GroupUserConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Membership already exists: {exc}",
        ) from exc
    except GroupUserOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced group or user not found: {exc}",
        ) from exc
    await session.commit()
    return GroupUserRead.model_validate(link)


@members_router.get(
    "/batch",
    response_model=BatchReadResult[GroupUserRead],
)
async def get_group_users_batch(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.READ))
    ],
    # Declared before `/{group_user_id}` so the static `/batch` path matches
    # ahead of the UUID path param. Default to an empty list so an omitted
    # `ids` param is valid (returns an empty result) rather than a 422.
    ids: Annotated[list[uuid.UUID], Query(default_factory=list)],
) -> BatchReadResult[GroupUserRead]:
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ids: at most 100 ids are allowed per batch read.",
        )
    service = GroupUserService(session, perm_filter)
    links = await service.get_many(ids)
    return BatchReadResult(
        items=[GroupUserRead.model_validate(link) if link is not None else None for link in links],
    )


@members_router.post(
    "/batch",
    response_model=BatchWriteResult[GroupUserRead],
)
async def write_group_users_batch(
    payload: GroupUserBatchWriteRequest,
    session: SessionDep,
    user_id: UserId,
    # Per-action filters resolved without raising so a batch that uses only
    # one action does not 403 on the other; the service denies per operation.
    # Declared before `/{group_user_id}` so the static `/batch` path matches
    # ahead of the UUID path param.
    create_filter: Annotated[
        SearchFilter[GroupUserModel] | None,
        Depends(depends_permissions_or_none(GroupUserModel, Action.CREATE)),
    ],
    delete_filter: Annotated[
        SearchFilter[GroupUserModel] | None,
        Depends(depends_permissions_or_none(GroupUserModel, Action.DELETE)),
    ],
) -> BatchWriteResult[GroupUserRead]:
    creator_id = await _require_user_id(user_id)
    service = GroupUserService(session)
    perm_filters = {
        Action.CREATE: create_filter,
        Action.DELETE: delete_filter,
    }
    try:
        results = await service.apply_batch(payload.operations, perm_filters, creator_id=creator_id)
    except BatchPermissionDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Batch operation denied: {exc}",
        ) from exc
    except GroupUserPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Membership falls outside your create scope: {exc}",
        ) from exc
    except GroupUserConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Membership already exists: {exc}",
        ) from exc
    except GroupUserOrphanError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced group or user not found: {exc}",
        ) from exc
    except GroupUserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membership not found: {exc}",
        ) from exc
    await session.commit()
    return BatchWriteResult(
        items=[
            GroupUserRead.model_validate(link) if link is not None else None for link in results
        ],
    )


@members_router.get("/{group_user_id}", response_model=GroupUserRead)
async def get_group_user(
    group_user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.READ))
    ],
) -> GroupUserRead:
    service = GroupUserService(session, perm_filter)
    try:
        link = await service.get(group_user_id)
    except GroupUserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membership not found: {exc}",
        ) from exc
    return GroupUserRead.model_validate(link)


@members_router.delete("/{group_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group_user(
    group_user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[GroupUserModel], Depends(depends_permissions(GroupUserModel, Action.DELETE))
    ],
) -> None:
    service = GroupUserService(session, perm_filter)
    try:
        await service.delete(group_user_id)
    except GroupUserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Membership not found: {exc}",
        ) from exc
    await session.commit()
