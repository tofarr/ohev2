"""FastAPI dependencies for auth resolution.

`get_current_user_id` resolves the authenticated principal from the request,
returning ``None`` when no principal is present (anonymous access). The
credential is a JWE-encrypted token supplied via, in priority order:

1. the ``X-API-Key`` header (an API-key JWE token),
2. the ``Authorization: Bearer <token>`` header (an OAuth2 access token), or
3. the ``ohesession`` cookie set by the login endpoint (a COOKIE token).

A token that is missing entirely means anonymous access (permissions with
``user_id IS NULL`` may still apply). A *present but invalid/expired* token is a
401: the client claimed a principal but the credential was bad.

When authentication succeeds via the **cookie** flow, the cookie is re-minted
with a fresh expiry (now + cookie timeout) and written to the response, so an
active browser session never expires while idle ones do (sliding session).

For the **auth2 federated** cookie (carrying an IdP access-token row id +
expiry), the cookie's lifetime is synced to the federated access token: when
it is about to expire the dependency performs a server-side refresh (gated by
a row lock) and re-mints the cookie, mirroring what a standard OAuth client
does at ``/auth2/refresh``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from openhands.ev2.auth.auth_service import AuthService, InvalidTokenError
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.db import SessionDep

# Security schemes double as OpenAPI documentation. Declared via `Security(...)`
# rather than `Header()` so FastAPI registers them in `components.securitySchemes`
# instead of surfacing them as per-operation header parameters. `auto_error=False`
# makes them optional so the three sources are tried in priority order; FastAPI
# emits one security requirement per scheme, so the docs present them as
# alternatives (either header satisfies the Authorize dialog). The session cookie
# is read directly from request.cookies (no FastAPI cookie security scheme), so
# it is not registered here.
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

# Claim keys for the auth2 federated session cookie (carried in the JWE so the
# dependency can detect imminent expiry and trigger a server-side refresh).
_AUTH2_ACCESS_ID_CLAIM = "aid"
_AUTH2_ACCESS_EXP_CLAIM = "axp"


async def get_current_user_id(
    request: Request,
    response: Response,
    session: SessionDep,
    x_api_key: Annotated[str | None, Security(_api_key_scheme)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer_scheme)] = None,
) -> uuid.UUID | None:
    """Resolve the current user id from a JWE auth token, or ``None``.

    Missing token ⇒ anonymous (None). Present-but-invalid token ⇒ 401. When the
    token is the session cookie, a fresh cookie is re-minted (sliding session);
    for an auth2 federated cookie that is about to expire, the federated access
    token is refreshed server-side first.
    """
    token = x_api_key
    used_cookie = False
    if token is None and bearer is not None:
        token = bearer.credentials
    if token is None:
        cookie_name = get_config().auth_cookie_name
        token = request.cookies.get(cookie_name)
        used_cookie = token is not None
    if token is None:
        return None

    service = AuthService(session)
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
        await _maybe_refresh_auth2_cookie(token, response, session, service)

    return auth_token.user_id


async def _maybe_refresh_auth2_cookie(
    token: str,
    response: Response,
    session: SessionDep,
    auth_service: AuthService,
) -> None:
    """Re-mint the session cookie, refreshing the federated access token if needed.

    A legacy (password-flow) cookie has no federated claims and is simply
    re-minted with a fresh expiry (sliding session). An auth2 federated cookie
    carries an IdP access-token row id + expiry; when that expiry is imminent
    (within the drift tolerance) the dependency triggers a server-side refresh
    (mirroring what a standard OAuth client does at ``/auth2/refresh``) before
    re-minting the cookie. On a concurrent-refresh lock timeout the existing
    cookie is kept so the client is not logged out; the next request retries.
    """
    from openhands.ev2.auth2.auth2_service import (
        Auth2Service,
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
    drift = timedelta(seconds=cfg.idp_expire_drift_tolerance)

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
    service = Auth2Service(session)
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


CurrentUserId = Annotated[uuid.UUID | None, Depends(get_current_user_id)]
