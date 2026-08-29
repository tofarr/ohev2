"""HTTP routes for the federated OAuth (auth) feature.

Endpoints (AGENTS.md §3 — standard verbs, plural resource names):

* ``GET  /auth/authorize`` — validate the client + redirect URI and redirect
  the browser to the IdP authorization endpoint. ``response_type`` is either
  ``code`` (standard OAuth: a code is returned after the callback) or ``cookie``
  (the callback sets a session cookie and returns no code).
* ``GET  /auth/callback``  — exchange the IdP code, JIT-provision the user,
  persist the encrypted IdP refresh token, set a session cookie, and redirect
  to the client's redirect URI. For ``response_type=code`` the redirect carries
  our authorization code + the original state; for ``response_type=cookie`` no
  code is returned (the cookie authenticates the browser).
* ``POST /auth/token``     — exchange our authorization code for an access +
  refresh token pair (RFC 6749 §4.1.3). Also handles the refresh grant.
* ``POST /auth/refresh``   — rotate the access + refresh pair via the IdP.
* ``POST /auth/revoke``    — revoke a token (RFC 7009). Refresh-token
  revocation is immediate; access-token revocation is best-effort (the
  JWE remains usable until its own short ``exp``).
* ``POST /auth/logout``    — cookie-focused session end. Revokes the
  federated session backing the session cookie (deleting the IdP refresh
  + access token rows) and clears the cookie. No client credentials
  required: the cookie *is* the credential.

OAuth client management is a REST resource at ``/auth/clients``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from openhands.ev2.auth.auth_dependencies import depends_access_token, depends_permissions
from openhands.ev2.auth.auth_models import AuthToken, OAuthClient
from openhands.ev2.auth.auth_schemas import (
    OAuthClientCreate,
    OAuthClientRead,
    OAuthClientSearchResult,
    OAuthClientUpdate,
    TokenRequest,
    TokenResponse,
    UserInfoResponse,
)
from openhands.ev2.auth.auth_service import (
    _RESPONSE_TYPE_COOKIE,
    AuthError,
    AuthService,
    IdpError,
    InvalidClientError,
    InvalidGrantError,
    InvalidRedirectUriError,
    RefreshLockTimeoutError,
    TokenPair,
    _seconds_until,
)
from openhands.ev2.config import get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.encryption.encryption_service import get_encryption_service
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/auth", tags=["auth"])


def _callback_url() -> str:
    """Derive the absolute callback URL from application config.

    Config-driven (rather than ``request.base_url``) so the URL is correct
    behind K8s ingresses / proxies that rewrite Host or scheme.
    """
    base_url = get_config().base_url.rstrip("/")
    return f"{base_url}/auth/callback"


def _set_session_cookie(
    response: RedirectResponse,
    *,
    user_id: uuid.UUID,
    access_id: uuid.UUID,
    access_expires_at: datetime,
) -> None:
    """Set an auth session cookie synced to the IdP access-token row.

    The cookie is a JWE carrying ``user_id``, ``access_token_id`` and the
    access-token expiry, so ``get_current_user_id`` can detect when it is about
    to expire and trigger a server-side refresh (mirroring what a standard
    OAuth client does at ``/auth/refresh``). The cookie's own max-age mirrors
    the access-token lifetime; it is re-minted on every refresh. SameSite is
    config-driven and defaults to ``strict`` (strongest XSRF mitigation); the
    cookie flow is a same-site flow so strict does not break it.
    """
    from openhands.ev2.auth.auth_service import _mint_cookie_jwe

    cfg = get_config()
    enc = get_encryption_service()
    cookie_token = _mint_cookie_jwe(
        enc,
        user_id=user_id,
        access_id=access_id,
        access_expires_at=access_expires_at,
    )
    response.set_cookie(
        key=cfg.auth_cookie_name,
        value=cookie_token,
        max_age=max(1, int((access_expires_at - datetime.now(UTC)).total_seconds())),
        httponly=True,
        samesite=cfg.auth_cookie_samesite,
        secure=cfg.auth_cookie_secure,
        path="/",
    )


def _error_status(exc: AuthError) -> int:
    if isinstance(exc, InvalidClientError):
        return status.HTTP_401_UNAUTHORIZED
    if isinstance(exc, InvalidRedirectUriError):
        return status.HTTP_400_BAD_REQUEST
    if isinstance(exc, InvalidGrantError):
        return status.HTTP_400_BAD_REQUEST
    if isinstance(exc, RefreshLockTimeoutError):
        # Concurrent refresh in progress; client should retry.
        return status.HTTP_409_CONFLICT
    if isinstance(exc, IdpError):
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_400_BAD_REQUEST


def _to_response(pair: TokenPair) -> TokenResponse:
    """Build a TokenResponse with synced federated expiries + optional id_token."""
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type="Bearer",
        expires_in=pair.expires_in,
        expires_at=pair.access_expires_at,
        refresh_token_expires_in=_seconds_until(pair.refresh_expires_at),
        refresh_token_expires_at=pair.refresh_expires_at,
        id_token=pair.id_token,
    )


@router.get("/authorize")
async def authorize(
    session: SessionDep,
    response_type: Annotated[Literal["code", "cookie"], Query()],
    client_id: Annotated[str, Query()],
    redirect_uri: Annotated[str, Query()],
    state: Annotated[str | None, Query()] = None,
    scope: Annotated[str | None, Query()] = None,
    code_challenge: Annotated[str | None, Query()] = None,
    code_challenge_method: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Validate the client + redirect URI and redirect to the IdP.

    ``response_type`` selects the provider-facing flow carried through to the
    callback:

    * ``code``   — standard OAuth (RFC 6749 §4.1.1). After the IdP redirects
      back, the callback mints an authorization code the client exchanges at
      ``/auth/token``.
    * ``cookie`` — a browser-oriented variant. After the IdP redirects back,
      the callback sets a session cookie and returns **no** code; the browser
      is authenticated by the cookie alone.

    Any other value is rejected by the OpenAPI-declared enum (HTTP 422).
    """
    service = AuthService(session)
    try:
        url = await service.build_authorize_redirect(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            callback_url=_callback_url(),
            response_type=response_type,
        )
    except AuthError as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    return RedirectResponse(
        url=url,
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/callback")
async def callback(
    session: SessionDep,
    code: Annotated[str, Query()],
    state: Annotated[str, Query()],
) -> RedirectResponse:
    """Exchange the IdP code and redirect to the client.

    Sets a session cookie on the redirect response. For ``response_type=code``
    the redirect goes to ``redirect_uri?code=…&state=…`` so the client can
    exchange the code at ``/auth/token``. For ``response_type=cookie`` no code
    is returned (the redirect carries only the optional ``state``); the session
    cookie authenticates the browser.
    """
    service = AuthService(session)
    try:
        ctx = await service.handle_callback(
            code=code,
            state=state,
            callback_url=_callback_url(),
        )
    except AuthError as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()

    params: dict[str, str] = {}
    if ctx.auth_code is not None:
        params["code"] = ctx.auth_code
    if ctx.client_state is not None:
        params["state"] = ctx.client_state
    location = f"{ctx.redirect_uri}?{urlencode(params)}" if params else ctx.redirect_uri
    response = RedirectResponse(
        url=location,
        status_code=status.HTTP_302_FOUND,
    )
    # The session cookie is the sole credential for the ``cookie`` response
    # type (a first-party browser flow). For the ``code`` response type the
    # client exchanges the code at ``/auth/token``; no cookie is minted, so a
    # confidential (token-based) client is never handed a browser session.
    if ctx.response_type == _RESPONSE_TYPE_COOKIE:
        _set_session_cookie(
            response,
            user_id=ctx.user_id,
            access_id=ctx.access_id,
            access_expires_at=ctx.access_expires_at,
        )
    return response


@router.post("/token", response_model=TokenResponse)
async def token(
    payload: TokenRequest,
    session: SessionDep,
) -> TokenResponse:
    """Exchange an authorization code (or refresh token) for our tokens.

    OAuth standard token endpoint (RFC 6749 §4.1.3 / §6): the
    ``authorization_code`` grant trades our short-lived code for an access +
    refresh token pair, and the ``refresh_token`` grant rotates that pair.
    """
    service = AuthService(session)
    try:
        if payload.grant_type == "authorization_code":
            if payload.code is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="code is required for authorization_code grant.",
                )
            pair = await service.exchange_authorization_code(
                code=payload.code,
                redirect_uri=payload.redirect_uri or "",
                client_id=payload.client_id,
                client_secret=payload.client_secret,
                code_verifier=payload.code_verifier,
            )
        elif payload.grant_type == "refresh_token":
            if payload.refresh_token is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="refresh_token is required for refresh_token grant.",
                )
            pair = await service.exchange_refresh_token(
                refresh_token=payload.refresh_token,
                client_id=payload.client_id,
                client_secret=payload.client_secret,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="grant_type must be 'authorization_code' or 'refresh_token'.",
            )
    except AuthError as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return _to_response(pair)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: TokenRequest,
    session: SessionDep,
) -> TokenResponse:
    """Rotate the access + refresh pair via the IdP (refresh grant).

    OAuth standard refresh-token grant (RFC 6749 §6): the existing refresh
    token is exchanged at the IdP for a fresh access + refresh pair. Both
    expiries are synced to the IdP response. A concurrent refresh of the same
    IdP token is gated by a row lock; on lock conflict the endpoint returns
    409 so the client can retry.
    """
    if payload.grant_type != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type must be 'refresh_token'.",
        )
    if payload.refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="refresh_token is required.",
        )
    service = AuthService(session)
    try:
        pair = await service.exchange_refresh_token(
            refresh_token=payload.refresh_token,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
        )
    except AuthError as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return _to_response(pair)


@router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke(
    token: Annotated[str, Form()],
    session: SessionDep,
    token_type_hint: Annotated[str | None, Form()] = None,
    client_id: Annotated[str, Form()] = "",
    client_secret: Annotated[str, Form()] = "",
) -> Response:
    """Revoke a token (RFC 7009).

    Form-encoded. Client credentials are validated (401 on failure); the token
    itself is best-effort — the endpoint always returns 200 and never reveals
    whether the token was valid, per §2.2. Refresh-token revocation is
    immediate (the federated session can no longer refresh); access-token
    revocation is best-effort (the JWE remains usable until its own short
    ``exp``).
    """
    service = AuthService(session)
    try:
        await service.revoke_token(
            token=token,
            token_type_hint=token_type_hint,
            client_id=client_id,
            client_secret=client_secret,
        )
    except InvalidClientError as exc:
        # Only client-auth failures are surfaced to the caller.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except AuthError:
        # Any other token error is swallowed (best-effort, RFC 7009 §2.2).
        pass
    finally:
        await service.aclose()
    await session.commit()
    return Response(status_code=status.HTTP_200_OK)


# ---------------------------------------------------------------------- #
# OIDC UserInfo (§5.3) — claims for the authenticated principal.
# ---------------------------------------------------------------------- #


@router.get("/userinfo", response_model=UserInfoResponse)
async def userinfo(
    session: SessionDep,
    token: Annotated[AuthToken, Depends(depends_access_token)],
) -> UserInfoResponse:
    """Return OIDC UserInfo claims for the authenticated principal.

    The access token (Bearer) authenticates the request; the granted scopes
    (carried in the token's ``scp`` claim) gate which claims are returned.
    Requires an ``openid``-scoped token; a token without ``openid`` returns
    only ``sub`` (per OIDC Core §5.4, ``sub`` is always returned).
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="An access token is required.",
        )
    service = AuthService(session)
    try:
        claims = await service.build_userinfo_claims(token.user_id, token.scopes)
    finally:
        await service.aclose()
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled.",
        )
    return UserInfoResponse(
        sub=claims.get("sub", str(token.user_id)),
        email=claims.get("email"),
        email_verified=claims.get("email_verified"),
        name=claims.get("name"),
        preferred_username=claims.get("preferred_username"),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
) -> Response:
    """End the browser session.

    Cookie-focused counterpart to ``/auth/revoke``: revokes the federated
    session backing the session cookie (deleting the IdP refresh + access
    token rows, best-effort forwarding to the IdP revocation endpoint) and
    clears the cookie. No client credentials are required — the cookie *is*
    the credential.

    Always returns 204 and clears the cookie, regardless of whether a cookie
    was present or whether its backing session was still live. The federated
    revocation is best-effort: a decrypt/parse failure or a missing backing
    row is swallowed, and the cookie is still cleared so the browser is logged
    out locally.
    """
    cfg = get_config()
    cookie_token = request.cookies.get(cfg.auth_cookie_name)
    if cookie_token is not None:
        service = AuthService(session)
        try:
            await service.revoke_session(cookie_token)
        except AuthError:
            pass
        finally:
            await service.aclose()
        await session.commit()
    response.delete_cookie(
        key=cfg.auth_cookie_name,
        httponly=True,
        samesite=cfg.auth_cookie_samesite,
        secure=cfg.auth_cookie_secure,
        path="/",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


# ---------------------------------------------------------------------- #
# OAuth clients — REST resource, permission-guarded.
# ---------------------------------------------------------------------- #


async def _to_read(service: AuthService, client: OAuthClient) -> OAuthClientRead:
    return OAuthClientRead(
        id=client.id,
        client_id=client.client_id,
        name=client.name,
        enabled=client.enabled,
        redirect_uris=await service.list_redirect_uris(client),
        created_at=client.created_at,
        updated_at=client.updated_at,
    )


@router.get(
    "/clients",
    response_model=OAuthClientSearchResult,
)
async def search_clients(
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(OAuthClient, Action.SEARCH))
    ],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OAuthClientSearchResult:
    """List OAuth clients, scoped to the principal's permission filter."""
    service = AuthService(session)
    try:
        cursor_uuid = uuid.UUID(cursor) if cursor is not None else None
        stmt = perm_filter.filter_sql(select(OAuthClient).order_by(OAuthClient.id))
        if cursor_uuid is not None:
            stmt = stmt.where(OAuthClient.id > cursor_uuid)
        stmt = stmt.limit(limit)
        result = await session.execute(stmt)
        clients = list(result.scalars().all())
        next_cursor = clients[-1].id if len(clients) == limit else None
        return OAuthClientSearchResult(
            items=[await _to_read(service, c) for c in clients],
            next_cursor=str(next_cursor) if next_cursor is not None else None,
            limit=limit,
        )
    finally:
        await service.aclose()


@router.post(
    "/clients",
    response_model=OAuthClientRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_client(
    payload: OAuthClientCreate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(OAuthClient, Action.CREATE))
    ],
) -> OAuthClientRead:
    """Register an OAuth client with an encrypted secret + redirect URIs."""
    service = AuthService(session)
    try:
        client = await service.create_client(
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            name=payload.name,
            redirect_uris=payload.redirect_uris,
            enabled=payload.enabled,
        )
    finally:
        await service.aclose()
    await session.commit()
    await session.refresh(client)
    return await _to_read(AuthService(session), client)


@router.get("/clients/{client_id}", response_model=OAuthClientRead)
async def get_client(
    client_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(OAuthClient, Action.READ))
    ],
) -> OAuthClientRead:
    """Retrieve an OAuth client by id, scoped to the principal."""
    service = AuthService(session)
    try:
        client = await service.get_client(client_id)
        if client is None or not perm_filter.matches(client):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OAuth client not found: {client_id}",
            )
        return await _to_read(service, client)
    finally:
        await service.aclose()


@router.patch("/clients/{client_id}", response_model=OAuthClientRead)
async def update_client(
    client_id: uuid.UUID,
    payload: OAuthClientUpdate,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(OAuthClient, Action.UPDATE))
    ],
) -> OAuthClientRead:
    """Partially update an OAuth client (rename, re-secret, re-uris, disable)."""
    service = AuthService(session)
    try:
        client = await service.get_client(client_id)
        if client is None or not perm_filter.matches(client):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OAuth client not found: {client_id}",
            )
        if payload.name is not None:
            client.name = payload.name
        if payload.client_secret is not None:
            client.client_secret = service._enc.encrypt_value(payload.client_secret)
        if payload.redirect_uris is not None:
            await service.replace_redirect_uris(client, payload.redirect_uris)
        if payload.enabled is not None:
            client.enabled = payload.enabled
        await session.flush()
        await session.refresh(client)
        read = await _to_read(service, client)
    finally:
        await service.aclose()
    await session.commit()
    return read


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(
    client_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any], Depends(depends_permissions(OAuthClient, Action.DELETE))
    ],
) -> None:
    """Delete an OAuth client by id, scoped to the principal."""
    service = AuthService(session)
    try:
        client = await service.get_client(client_id)
        if client is None or not perm_filter.matches(client):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OAuth client not found: {client_id}",
            )
        await service.delete_client(client)
    finally:
        await service.aclose()
    await session.commit()
