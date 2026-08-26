"""HTTP routes for the user feature.

Follows the uniform REST surface (AGENTS.md §3): GET /users (paginated),
POST /users, GET/PATCH/DELETE /users/{id}. Handlers validate, call the
service, and serialize — no business logic here. Every endpoint is guarded by
the centralized permission checker (AGENTS.md §9); the returned
:class:`SearchFilter` is passed into the service constructor so search/update/
delete SQL and create payloads are scoped to the principal.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ohev.config import get_config
from ohev.permission.permission_dependencies import (
    SessionDep,
    require_permission,
)
from ohev.permission.permission_models import Action, ResourceType
from ohev.user.user_models import User
from ohev.user.user_schemas import (
    LoginResponse,
    UserCreate,
    UserLogin,
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
    UserUsernameConflictError,
)
from ohev.util.auth_token import create_auth_token
from ohev.util.schemas import CountResult
from ohev.util.search_filter import SearchFilter

router = APIRouter(prefix="/users", tags=["users"])


def _set_auth_cookie(response: Response, token: str) -> None:
    """Set the session cookie carrying the JWE auth token (AGENTS.md §9)."""
    cfg = get_config()
    response.set_cookie(
        key=cfg.auth_cookie_name,
        value=token,
        max_age=cfg.auth_token_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=cfg.auth_cookie_secure,
        path="/",
    )


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
    service = UserService(session, perm_filter)
    cursor_uuid = _cursor(cursor) if cursor is not None else None
    users, next_cursor = await service.search_users(
        cursor=cursor_uuid,
        limit=limit,
        search_filter=search_filter,
    )
    return UserSearchResult(
        items=[UserRead.model_validate(u) for u in users],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.get(
    "/count",
    response_model=CountResult,
)
async def count_users(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[User], Depends(require_permission(Action.SEARCH, ResourceType.USER))
    ],
    # See search_users: bare `Depends()` lets FastAPI explode the filter model's
    # fields as query params. Declared before `/{user_id}` so the static path
    # matches ahead of the UUID path param.
    search_filter: UserSearchFilter = Depends(),  # noqa: B008
) -> CountResult:
    service = UserService(session, perm_filter)
    total = await service.count(search_filter=search_filter)
    return CountResult(count=total)


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
    service = UserService(session, perm_filter)
    try:
        user = await service.create(payload)
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
    except UserUsernameConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with username already exists: {exc}",
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
    service = UserService(session, perm_filter)
    try:
        user = await service.get(user_id)
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
    service = UserService(session, perm_filter)
    try:
        user = await service.update(user_id, payload)
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
    except UserUsernameConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with username already exists: {exc}",
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
    service = UserService(session, perm_filter)
    try:
        await service.delete(user_id)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {exc}",
        ) from exc
    await session.commit()


@router.post(
    "/login",
    response_model=LoginResponse,
)
async def login(
    payload: UserLogin,
    session: SessionDep,
    response: Response,
) -> LoginResponse:
    """Authenticate by username/password and set a JWE auth cookie.

    Does not require a permission grant: it is the entry point that mints an
    auth token. Returns 401 on bad credentials, a disabled account, or no
    password set.
    """
    service = UserService(session)
    user = await service.authenticate(payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    token = create_auth_token(user.id)
    _set_auth_cookie(response, token)
    await session.commit()
    return LoginResponse(user=UserRead.model_validate(user))


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def logout(response: Response) -> None:
    """Clear the session cookie, ending the authenticated session.

    Mirrors ``login``: like login it needs no permission grant, since clearing
    a cookie is harmless when none is present and is the entry point's inverse.
    The cookie is expired by setting ``max_age=0`` so browsers delete it
    immediately (AGENTS.md §9).
    """
    cfg = get_config()
    response.delete_cookie(
        key=cfg.auth_cookie_name,
        path="/",
        httponly=True,
        samesite="lax",
        secure=cfg.auth_cookie_secure,
    )
