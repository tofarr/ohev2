"""HTTP routes for the user feature.

Follows the uniform REST surface (AGENTS.md §3): GET /users (paginated),
POST /users, GET/PATCH/DELETE /users/{id}. Handlers validate, call the
service, and serialize — no business logic here. Every endpoint is guarded by
the centralized permission checker (AGENTS.md §9); the returned
:class:`SearchFilter` is passed to the service so search/update/delete SQL and
create payloads are scoped to the principal.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ohev.permission.permission_dependencies import (
    SessionDep,
    require_permission,
)
from ohev.permission.permission_models import Action, ResourceType
from ohev.user.user_models import User
from ohev.user.user_schemas import (
    UserCreate,
    UserRead,
    UserSearchFilter,
    UserSearchResult,
    UserUpdate,
)
from ohev.user.user_service import (
    UserEmailConflictError,
    UserNotFoundError,
    UserPermissionScopeError,
    UserService,
)
from ohev.util.search_filter import SearchFilter

router = APIRouter(prefix="/users", tags=["users"])


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.get(
    "",
    response_model=UserSearchResult,
)
async def search_users(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.SEARCH, ResourceType.USER))
    ],
    # `Depends()` (bare) lets FastAPI use the type annotation as the dependency
    # callable and explode the model's fields as individual query params. A
    # factory or `Annotated[..., Query()]` would NOT populate fields from query
    # strings when sibling scalar `Query()` params are present.
    search_filter: UserSearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query(description="Opaque UUID cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> UserSearchResult:
    service = UserService(session)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    users, next_cursor = await service.search_users(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
        perm_filter=perm_filter,
    )
    return UserSearchResult(
        items=[UserRead.model_validate(u) for u in users],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    payload: UserCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.CREATE, ResourceType.USER))
    ],
) -> UserRead:
    service = UserService(session)
    try:
        user = await service.create(payload, perm_filter)
    except UserPermissionScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User falls outside your create scope: {exc}",
        ) from exc
    except UserEmailConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email already exists: {exc}",
        ) from exc
    await session.commit()
    return UserRead.model_validate(user)


@router.get(
    "/{user_id}",
    response_model=UserRead,
)
async def get_user(
    user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.READ, ResourceType.USER))
    ],
) -> UserRead:
    service = UserService(session)
    try:
        user = await service.get(user_id, perm_filter)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    return UserRead.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserRead,
)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.UPDATE, ResourceType.USER))
    ],
) -> UserRead:
    service = UserService(session)
    try:
        user = await service.update(user_id, payload, perm_filter)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    except UserEmailConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email already exists: {exc}",
        ) from exc
    await session.commit()
    return UserRead.model_validate(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user(
    user_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.DELETE, ResourceType.USER))
    ],
) -> None:
    service = UserService(session)
    try:
        await service.delete(user_id, perm_filter)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    await session.commit()
