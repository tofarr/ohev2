"""FastAPI dependencies for federated (auth) auth + authorization resolution.

This module resolves the authenticated principal from a federated credential,
caches the per-request work so subsequent dependencies in the same request reuse
it, and provides both role-based and policy-based authorization guards.

Credential resolution priority:

1. the ``Authorization: Bearer <token>`` header — an auth access-token JWE
   (``ttyp: access_token``), or a legacy auth access-token / API-key JWE.
2. the session cookie (``ttyp: cookie``) set by the auth callback.

A token that is missing entirely means anonymous access (permissions with
``user_id IS NULL`` may still apply). A *present but invalid/expired* token is
a 401. When the cookie flow is used and the federated access token backing it
is about to expire, the dependency refreshes it server-side (mirroring
``/auth/refresh``) and re-mints the cookie (sliding session).

The decrypted :class:`AuthToken` is cached on ``request.state`` so
``depends_access_token``, ``depends_user_id``, ``depends_roles`` and
``depends_permissions`` all share one decryption + one DB user lookup per
request. Roles are likewise cached on the request when the count is small
enough to materialize cheaply (see ``depends_roles``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import AuthToken
from openhands.ev2.auth.auth_tokens import InvalidTokenError, TokenService
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.security.security_models import Action, Permission, Role, RoleUser
from openhands.ev2.util.search_filter import (
    ALL_SEARCH_FILTER,
    AllSearchFilter,
    NoneSearchFilter,
    OrSearchFilter,
    SearchFilter,
)

# Security schemes double as OpenAPI documentation. Declared via `Security(...)`
# rather than `Header()` so FastAPI registers them in `components.securitySchemes`
# instead of surfacing them as per-operation header parameters. `auto_error=False`
# makes them optional so the three sources are tried in priority order; FastAPI
# emits one security requirement per scheme, so the docs present them as
# alternatives. The session cookie is read directly from request.cookies (no
# FastAPI cookie security scheme), so it is not registered here.
_api_key_scheme = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ApiKey",
    auto_error=False,
    description="API key (JWE) sent in the X-API-Key header.",
)
_bearer_scheme = HTTPBearer(
    scheme_name="BearerAuth",
    auto_error=False,
    description="OAuth2 access token (JWE) sent as `Authorization: Bearer <token>`.",
)

# Request-state keys for the per-request caches. Storing on request.state lets
# multiple dependencies in the same request share one decrypted token / one
# role fetch without a shared global.
_ACCESS_TOKEN_KEY = "_auth_access_token"
_ROLES_KEY = "_auth_roles"

# When a principal has fewer than this many roles, the full list is materialized
# and cached on the request so ``depends_roles`` can iterate without re-querying.
_ROLES_CACHE_THRESHOLD = 100

# Claim keys for the auth federated session cookie (carried in the JWE so the
# dependency can detect imminent expiry and trigger a server-side refresh).
_AUTH2_ACCESS_ID_CLAIM = "aid"
_AUTH2_ACCESS_EXP_CLAIM = "axp"


# ---------------------------------------------------------------------- #
# Token resolution.
# ---------------------------------------------------------------------- #


async def depends_access_token(
    request: Request,
    response: Response,
    session: SessionDep,
    x_api_key: Annotated[str | None, Security(_api_key_scheme)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer_scheme)] = None,
) -> AuthToken | None:
    """Resolve the current principal from a credential, or ``None``.

    The credential is a JWE-encrypted token supplied via, in priority order:

    1. the ``X-API-Key`` header (an API-key JWE token),
    2. the ``Authorization: Bearer <token>`` header (an OAuth2 access token), or
    3. the session cookie set by the login / auth callback endpoint.

    The decrypted :class:`AuthToken` is cached on ``request.state`` so
    ``depends_user_id``, ``depends_roles`` and ``depends_permissions`` reuse it
    without re-decrypting or re-loading the user row.

    Missing token => anonymous (None). Present-but-invalid token => 401. When the
    token is the session cookie, a fresh cookie is re-minted (sliding session);
    for an auth federated cookie that is about to expire, the federated access
    token is refreshed server-side first.
    """
    cached = getattr(request.state, _ACCESS_TOKEN_KEY, None)
    if cached is not None:
        return cached if cached is not _ANON_SENTINEL else None

    token = x_api_key
    used_cookie = False
    if token is None and bearer is not None:
        token = bearer.credentials
    if token is None:
        cookie_name = get_config().auth_cookie_name
        token = request.cookies.get(cookie_name)
        used_cookie = token is not None
    if token is None:
        _cache_token(request, _ANON_SENTINEL)
        return None

    service = TokenService(session)
    try:
        auth_token = await service.authenticate(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired auth token.",
        ) from exc

    # A token that decrypts but whose backing row is disabled (e.g. a revoked
    # API key) authenticates as nobody.
    if not auth_token.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired auth token.",
        )

    if used_cookie:
        await _maybe_refresh_auth_cookie(token, response, session, service)

    _cache_token(request, auth_token)
    return auth_token


def _cache_token(request: Request, value: AuthToken | Any) -> None:
    setattr(request.state, _ACCESS_TOKEN_KEY, value)


async def _maybe_refresh_auth_cookie(
    token: str,
    response: Response,
    session: AsyncSession,
    auth_service: TokenService,
) -> None:
    """Re-mint the session cookie, refreshing the federated access token if needed.

    A legacy (password-flow) cookie has no federated claims and is simply
    re-minted with a fresh expiry (sliding session). An auth federated cookie
    carries an IdP access-token row id + expiry; when that expiry is imminent
    (within the drift tolerance) the dependency triggers a server-side refresh
    (mirroring what a standard OAuth client does at ``/auth/refresh``) before
    re-minting the cookie. On a concurrent-refresh lock timeout the existing
    cookie is kept so the client is not logged out; the next request retries.
    """
    from openhands.ev2.auth.auth_service import (
        AuthService,
        RefreshLockTimeoutError,
        _mint_cookie_jwe,
    )
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    cfg = get_config()
    enc = get_encryption_service()
    payload = enc.decrypt_jwe_token(token)
    access_id_raw = payload.get(_AUTH2_ACCESS_ID_CLAIM)

    if not isinstance(access_id_raw, str):
        # Legacy (password-flow) cookie: plain sliding re-mint.
        fresh = auth_service.reissue_cookie(_user_sub(payload))
        _set_cookie(response, fresh, cfg.auth_cookie_timeout_seconds, cfg)
        return

    access_id = uuid.UUID(access_id_raw)
    access_exp = _access_exp(payload)
    drift = timedelta(seconds=cfg.idp.expire_drift_tolerance)

    if access_exp is None or access_exp > datetime.now(UTC) + drift:
        # Not imminent: re-mint off the existing (synced) expiry.
        if access_exp is None:
            fresh = auth_service.reissue_cookie(_user_sub(payload))
            _set_cookie(response, fresh, cfg.auth_cookie_timeout_seconds, cfg)
            return
        fresh = _mint_cookie_jwe(
            enc,
            user_id=_user_sub(payload),
            access_id=access_id,
            access_expires_at=access_exp,
        )
        _set_cookie(
            response,
            fresh,
            max(1, int((access_exp - datetime.now(UTC)).total_seconds())),
            cfg,
        )
        return

    # Imminent/expired: refresh the federated access token under a row lock.
    service = AuthService(session)
    try:
        access_row, _ = await service.refresh_access_token(access_id)
        await session.commit()
    except RefreshLockTimeoutError:
        # Concurrent refresh holds the lock; keep the existing cookie valid this
        # request. The next request retries the refresh.
        fresh = _mint_cookie_jwe(
            enc,
            user_id=_user_sub(payload),
            access_id=access_id,
            access_expires_at=access_exp,
        )
        _set_cookie(
            response,
            fresh,
            max(1, int((access_exp - datetime.now(UTC)).total_seconds())),
            cfg,
        )
        return
    finally:
        await service.aclose()

    fresh = _mint_cookie_jwe(
        enc,
        user_id=_user_sub(payload),
        access_id=access_row.id,
        access_expires_at=access_row.expires_at,
    )
    _set_cookie(
        response,
        fresh,
        max(1, int((access_row.expires_at - datetime.now(UTC)).total_seconds())),
        cfg,
    )


def _user_sub(payload: dict[str, object]) -> uuid.UUID:
    raw = payload.get("sub")
    if not isinstance(raw, str):
        raise InvalidTokenError("missing subject")
    return uuid.UUID(raw)


def _access_exp(payload: dict[str, object]) -> datetime | None:
    raw = payload.get(_AUTH2_ACCESS_EXP_CLAIM)
    if not isinstance(raw, int | float):
        return None
    return datetime.fromtimestamp(int(raw), tz=UTC)


def _set_cookie(response: Response, value: str, max_age: int, cfg: AppConfig) -> None:
    response.set_cookie(
        key=cfg.auth_cookie_name,
        value=value,
        max_age=max_age,
        httponly=True,
        samesite=cfg.auth_cookie_samesite,
        secure=cfg.auth_cookie_secure,
        path="/",
    )


# A sentinel distinct from any AuthToken so the anonymous result (None) is
# cached on request.state without colliding with "not yet resolved" (also None
# when read via getattr with a default).
_ANON_SENTINEL: Any = object()


# ---------------------------------------------------------------------- #
# User id.
# ---------------------------------------------------------------------- #


async def depends_user_id(
    token: Annotated[AuthToken | None, Depends(depends_access_token)],
) -> uuid.UUID | None:
    """The current principal's user id, or ``None`` for anonymous access.

    Reuses the cached :class:`AuthToken` resolved by
    :func:`depends_access_token` so no second decryption / DB lookup occurs.
    """
    return token.user_id if token is not None else None


# ---------------------------------------------------------------------- #
# Roles.
# ---------------------------------------------------------------------- #


async def depends_roles(
    request: Request,
    session: SessionDep,
    token: Annotated[AuthToken | None, Depends(depends_access_token)],
) -> AsyncIterator[Role]:
    """Yield the roles assigned to the current principal.

    Returns an async iterator over the :class:`Role` rows assigned to the
    principal via the ``role_users`` link table. Anonymous principals (no
    token) yield no roles.

    When the principal has fewer than ``_ROLES_CACHE_THRESHOLD`` roles the full
    list is materialized and cached on ``request.state`` so subsequent
    dependencies (e.g. ``depends_permissions``) in the same request iterate
    without re-querying the database. Above the threshold the roles are streamed
    directly from the session and not cached, avoiding loading a large set into
    memory at once.
    """
    if token is None:
        return
    async for role in _iter_roles(request, session, token.user_id):
        yield role


_ROLES_MISSING: Any = object()


async def _iter_roles(
    request: Request,
    session: AsyncSession,
    user_id: uuid.UUID,
) -> AsyncIterator[Role]:
    """Yield roles for *user_id*, caching on the request when the set is small.

    Serves from the per-request cache when present. Otherwise loads all roles;
    if the count is below ``_ROLES_CACHE_THRESHOLD`` the list is cached on
    ``request.state`` for reuse by later dependencies in the same request.
    Above the threshold the roles are streamed and not cached.
    """
    cached = getattr(request.state, _ROLES_KEY, _ROLES_MISSING)
    if cached is not _ROLES_MISSING:
        for role in cached:
            yield role
        return

    roles = await _load_roles(session, user_id)

    if len(roles) < _ROLES_CACHE_THRESHOLD:
        setattr(request.state, _ROLES_KEY, roles)
        for role in roles:
            yield role
        return

    # Above the threshold: stream without caching. The materialized list above
    # is discarded; the streaming query re-fetches from the DB cursor.
    async for role in _stream_roles(session, user_id):
        yield role


async def _load_roles(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
    """Materialize all roles for *user_id* in one query."""
    stmt = (
        select(Role).join(RoleUser, RoleUser.role_id == Role.id).where(RoleUser.user_id == user_id)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _stream_roles(session: AsyncSession, user_id: uuid.UUID) -> AsyncIterator[Role]:
    """Yield roles for *user_id* one at a time from the DB cursor."""
    stmt = (
        select(Role)
        .join(RoleUser, RoleUser.role_id == Role.id)
        .where(RoleUser.user_id == user_id)
        .execution_options(yield_per=1)
    )
    result = await session.stream(stmt)
    async for role in result.scalars():
        yield role
    await result.close()


# ---------------------------------------------------------------------- #
# Permissions (policy-based search filter).
# ---------------------------------------------------------------------- #

# Maps a resource's ORM model class to the resource-type name used as the key in
# a Role's ``policies`` JSONB map. Resources without an entry default to deny.
# New resources register here (or call ``register_resource_policy``) so
# depends_permissions can find their policy without editing the function body.
_RESOURCE_POLICY: dict[type, str] = {}


def register_resource_policy(model: type, resource_type: str) -> None:
    """Register the resource-type name that governs *model*.

    Resources register their ORM model class against the key used in a Role's
    ``policies`` map (e.g. ``"user"``, ``"api_key"``). This keeps the policy
    lookup table in one place and lets new resources opt in without editing
    ``depends_permissions``.
    """
    _RESOURCE_POLICY[model] = resource_type


# Register every shipped resource at import time so the mapping is populated
# before any request runs. Resource-type names are lowercased resource nouns.
from openhands.ev2.auth.auth_models import ApiKey as _ApiKey  # noqa: E402
from openhands.ev2.auth.auth_models import OAuthClient as _OAuthClient  # noqa: E402
from openhands.ev2.cors.cors_models import AllowedOrigin as _AllowedOrigin  # noqa: E402
from openhands.ev2.security.security_models import Role as _Role  # noqa: E402
from openhands.ev2.user.user_models import User as _User  # noqa: E402

register_resource_policy(_User, "user")
register_resource_policy(_Role, "role")
register_resource_policy(_ApiKey, "api_key")
register_resource_policy(_OAuthClient, "oauth_client")
register_resource_policy(_AllowedOrigin, "cors_origin")


def depends_permissions(
    model_type: type,
    action: Action,
) -> Callable[..., Coroutine[Any, Any, SearchFilter[Any]]]:
    """Build a FastAPI dependency that authorizes *action* on *model_type*.

    Reduces every :class:`Permission` policy on the principal's roles for the
    resource governing *model_type* to a :class:`SearchFilter` for
    ``(user_id, action)``, combining them with ``Or``. Returns the effective
    filter so services can scope search/update/delete SQL and validate creates.
    Raises 403 Forbidden when no grant applies (the combined filter is a deny).

    Usage::

        @router.get("")
        async def search_users(
            perm_filter: SearchFilter[User] = Depends(
                depends_permissions(User, Action.SEARCH)
            ),
            ...,
        ): ...

    Anonymous principals (no token) have no roles, so they are denied (403)
    unless a future anonymous-role mechanism grants access.
    """

    async def _guard(
        request: Request,
        session: SessionDep,
        token: Annotated[AuthToken | None, Depends(depends_access_token)],
    ) -> SearchFilter[Any]:
        user_id = token.user_id if token is not None else None
        resource_type = _policy_attr_for(model_type)
        if resource_type is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Permission denied: no policy registered for "
                    f"{model_type.__name__} action={action.value}"
                ),
            )

        filters: list[SearchFilter[Any]] = []
        async for role in depends_roles(request, session, token):
            policy = _role_policy_for(role, resource_type)
            if policy is None:
                continue
            filters.append(policy.to_search_filter(user_id, action))

        effective = _combine(filters)
        if effective is None or isinstance(effective, NoneSearchFilter):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"Permission denied: action={action.value} resource={model_type.__name__}"),
            )
        return effective

    return _guard


def _policy_attr_for(model_type: type) -> str | None:
    """The resource-type name governing *model_type*, or ``None``."""
    return _RESOURCE_POLICY.get(model_type)


def _role_policy_for(role: Role, resource_type: str) -> Permission | None:
    """The :class:`Permission` policy for *resource_type* on *role*.

    Reads from the Role's ``policies`` map (the canonical store). Falls back to
    the legacy ``role_permission`` / ``user_permission`` columns for roles
    created before the ``policies`` column existed, so existing data continues
    to authorize during the migration.
    """
    policies = role.policies
    if policies is not None and resource_type in policies:
        return policies[resource_type]
    if resource_type == "user":
        return role.user_permission
    if resource_type in ("role", "permission"):
        return role.role_permission
    return None


def _combine(filters: list[SearchFilter[Any]]) -> SearchFilter[Any] | None:
    """Combine per-role filters into one, or ``None`` when there are none.

    A single filter is returned as-is. Multiple filters are ORed: the principal
    sees the union of what any of their roles grants. An empty list means no
    policy applied to any of the principal's roles, which is a deny
    (the caller raises 403).
    """
    if not filters:
        return None
    if len(filters) == 1:
        return filters[0]
    return OrSearchFilter(filters=filters)


# ---------------------------------------------------------------------- #
# Annotated aliases for convenient injection.
# ---------------------------------------------------------------------- #

AccessToken = Annotated[AuthToken | None, Depends(depends_access_token)]
UserId = Annotated[uuid.UUID | None, Depends(depends_user_id)]


__all__ = [
    "ALL_SEARCH_FILTER",
    "AccessToken",
    "AllSearchFilter",
    "NoneSearchFilter",
    "UserId",
    "depends_access_token",
    "depends_permissions",
    "depends_roles",
    "depends_user_id",
    "register_resource_policy",
]
