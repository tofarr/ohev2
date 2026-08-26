"""HTTP routes for the auth feature.

Two authentication flows (AGENTS.md §9):

* **Password / Cookie flow** — `POST /auth/login` validates username/password
  and sets a session cookie; `POST /auth/logout` clears it. Each subsequent
  authenticated request re-mints the cookie (sliding session) in
  :func:`get_current_user_id`.
* **OAuth2 flow** — `POST /auth/token` (password grant) issues an access token
  + refresh token pair; `POST /auth/refresh` (refresh grant) rotates the pair.

API keys are managed as a REST resource at `/auth/api-keys`: mint (returns the
raw JWE token once), list, update (enable/disable, rename, re-expire), delete.
All management endpoints are permission-guarded; minting is scoped to the
current user.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select

from ohev.auth.auth_dependencies import CurrentUserId
from ohev.auth.auth_schemas import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyRead,
    ApiKeySearchFilter,
    ApiKeySearchResult,
    ApiKeyUpdate,
    LoginRequest,
    LoginResponse,
    OAuthTokenRequest,
    OAuthTokenResponse,
    RefreshRequest,
)
from ohev.auth.auth_service import AuthService, InvalidTokenError
from ohev.config import get_config
from ohev.db import SessionDep
from ohev.permission.permission_dependencies import require_permission
from ohev.permission.permission_models import Action, ResourceType
from ohev.user.user_service import UserService
from ohev.util.search_filter import SearchFilter

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_auth_cookie(response: Response, token: str) -> None:
    """Set the session cookie carrying the JWE cookie token (AGENTS.md §9)."""
    cfg = get_config()
    response.set_cookie(
        key=cfg.auth_cookie_name,
        value=token,
        max_age=cfg.auth_cookie_timeout_seconds,
        httponly=True,
        samesite="lax",
        secure=cfg.auth_cookie_secure,
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    """Clear the session cookie by setting max-age=0 (AGENTS.md §9)."""
    cfg = get_config()
    response.delete_cookie(
        key=cfg.auth_cookie_name,
        path="/",
        httponly=True,
        samesite="lax",
        secure=cfg.auth_cookie_secure,
    )


def _cursor(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor; expected a UUID.",
        ) from exc


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    session: SessionDep,
    response: Response,
) -> LoginResponse:
    """Authenticate by username/password and set a JWE session cookie.

    No permission grant required: this is the entry point that mints the
    credential. Returns 401 on bad credentials, a disabled account, or no
    password set.
    """
    service = UserService(session)
    user = await service.authenticate(payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    token = AuthService(session).create_cookie_token(user.id)
    _set_auth_cookie(response, token)
    await session.commit()
    return LoginResponse(user_id=user.id, username=user.username)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    """Clear the session cookie, ending the authenticated session.

    No permission grant required: clearing a cookie is harmless when none is
    present and is login's inverse.
    """
    _clear_auth_cookie(response)


@router.post("/token", response_model=OAuthTokenResponse)
async def token(
    payload: OAuthTokenRequest,
    session: SessionDep,
) -> OAuthTokenResponse:
    """OAuth2 password grant: issue an access + refresh token pair.

    No permission grant required: this mints credentials from username/password.
    Returns 401 on bad credentials and 400 on an unsupported grant_type.
    """
    if payload.grant_type != "password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type must be 'password'.",
        )
    service = UserService(session)
    user = await service.authenticate(payload.username, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    auth = AuthService(session)
    access = auth.create_access_token(user.id)
    refresh, _jti = await auth.create_refresh_token(user.id)
    await session.commit()
    cfg = get_config()
    return OAuthTokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=cfg.auth_access_token_ttl_seconds,
    )


@router.post("/refresh", response_model=OAuthTokenResponse)
async def refresh(
    payload: RefreshRequest,
    session: SessionDep,
) -> OAuthTokenResponse:
    """OAuth2 refresh grant: rotate the access/refresh pair.

    Returns 400 on an unsupported grant_type and 401 on an invalid/revoked
    refresh token.
    """
    if payload.grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type must be 'refresh_token'.",
        )
    auth = AuthService(session)
    try:
        access, refresh, _user_id = await auth.refresh(payload.refresh_token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        ) from exc
    await session.commit()
    cfg = get_config()
    return OAuthTokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=cfg.auth_access_token_ttl_seconds,
    )


# ----------------------------------------------------------------------
# API keys — REST resource, permission-guarded.
# ----------------------------------------------------------------------


@router.get(
    "/api-keys",
    response_model=ApiKeySearchResult,
)
async def search_api_keys(
    session: SessionDep,
    user_id: CurrentUserId,
    perm_filter: Annotated[
        SearchFilter[Any],
        Depends(require_permission(Action.SEARCH, ResourceType.API_KEY)),
    ],
    search_filter: ApiKeySearchFilter = Depends(),  # noqa: B008
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ApiKeySearchResult:
    """List API keys, scoped to the principal's permission filter and
    additionally to the current user (a key's owner may always see their own)."""
    from ohev.auth.auth_models import ApiKey

    cursor_uuid = _cursor(cursor) if cursor is not None else None
    stmt = perm_filter.filter_sql(select(ApiKey).order_by(ApiKey.id))
    if search_filter is not None:
        stmt = search_filter.filter_sql(stmt)
    # An owner always sees their own keys, even without a broad grant.
    stmt = stmt.where(ApiKey.user_id == user_id)
    if cursor_uuid is not None:
        stmt = stmt.where(ApiKey.id > cursor_uuid)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    keys = list(result.scalars().all())
    next_cursor = keys[-1].id if len(keys) == limit else None
    return ApiKeySearchResult(
        items=[ApiKeyRead.model_validate(k) for k in keys],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
        limit=limit,
    )


@router.post(
    "/api-keys",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    payload: ApiKeyCreate,
    session: SessionDep,
    user_id: CurrentUserId,
) -> ApiKeyCreateResponse:
    """Mint an API key for the current user.

    The raw token is returned only here; it is never retrievable again.
    """
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to create an API key.",
        )
    auth = AuthService(session)
    token, row = await auth.create_api_key(
        user_id, name=payload.name, expires_at=payload.expires_at
    )
    await session.commit()
    return ApiKeyCreateResponse(api_key=ApiKeyRead.model_validate(row), token=token)


@router.get(
    "/api-keys/{api_key_id}",
    response_model=ApiKeyRead,
)
async def get_api_key(
    api_key_id: uuid.UUID,
    session: SessionDep,
    user_id: CurrentUserId,
    perm_filter: Annotated[
        SearchFilter[Any],
        Depends(require_permission(Action.READ, ResourceType.API_KEY)),
    ],
) -> ApiKeyRead:
    """Retrieve an API key by id, scoped to the principal."""
    from ohev.auth.auth_models import ApiKey

    stmt = perm_filter.filter_sql(select(ApiKey).where(ApiKey.id == api_key_id))
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None or row.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {api_key_id}",
        )
    return ApiKeyRead.model_validate(row)


@router.patch(
    "/api-keys/{api_key_id}",
    response_model=ApiKeyRead,
)
async def update_api_key(
    api_key_id: uuid.UUID,
    payload: ApiKeyUpdate,
    session: SessionDep,
    user_id: CurrentUserId,
    perm_filter: Annotated[
        SearchFilter[Any],
        Depends(require_permission(Action.UPDATE, ResourceType.API_KEY)),
    ],
) -> ApiKeyRead:
    """Partially update an API key (enable/disable, rename, re-expire)."""
    from ohev.auth.auth_models import ApiKey

    stmt = perm_filter.filter_sql(select(ApiKey).where(ApiKey.id == api_key_id))
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None or row.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {api_key_id}",
        )
    if payload.name is not None:
        row.name = payload.name
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.expires_at is not None:
        row.expires_at = payload.expires_at
    await session.flush()
    await session.refresh(row)
    await session.commit()
    return ApiKeyRead.model_validate(row)


@router.delete(
    "/api-keys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_api_key(
    api_key_id: uuid.UUID,
    session: SessionDep,
    user_id: CurrentUserId,
    perm_filter: Annotated[
        SearchFilter[Any],
        Depends(require_permission(Action.DELETE, ResourceType.API_KEY)),
    ],
) -> None:
    """Delete (revoke) an API key by id, scoped to the principal."""
    from ohev.auth.auth_models import ApiKey

    stmt = perm_filter.filter_sql(select(ApiKey).where(ApiKey.id == api_key_id))
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None or row.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {api_key_id}",
        )
    await session.delete(row)
    await session.commit()
