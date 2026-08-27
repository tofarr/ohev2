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
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from openhands.ev2.auth.auth_service import AuthService, InvalidTokenError
from openhands.ev2.config import get_config
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


async def get_current_user_id(
    request: Request,
    response: Response,
    session: SessionDep,
    x_api_key: Annotated[str | None, Security(_api_key_scheme)] = None,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer_scheme)] = None,
) -> uuid.UUID | None:
    """Resolve the current user id from a JWE auth token, or ``None``.

    Missing token ⇒ anonymous (None). Present-but-invalid token ⇒ 401. When the
    token is the session cookie, a fresh cookie is re-minted (sliding session).
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
        # Sliding session: re-mint the cookie with a fresh expiry on every
        # authenticated request (AGENTS.md §9).
        cfg = get_config()
        fresh = service.reissue_cookie(auth_token.user_id)
        response.set_cookie(
            key=cfg.auth_cookie_name,
            value=fresh,
            max_age=cfg.auth_cookie_timeout_seconds,
            httponly=True,
            samesite=cfg.auth_cookie_samesite,
            secure=cfg.auth_cookie_secure,
            path="/",
        )
    return auth_token.user_id


CurrentUserId = Annotated[uuid.UUID | None, Depends(get_current_user_id)]
