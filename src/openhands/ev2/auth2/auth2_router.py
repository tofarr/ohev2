"""HTTP routes for the federated OAuth (auth2) feature.

Endpoints (AGENTS.md §3 — standard verbs, plural resource names):

* ``GET  /auth2/authorize`` — validate the client + redirect URI and redirect
  the browser to the IdP authorization endpoint. ``response_type`` is either
  ``code`` (standard OAuth: a code is returned after the callback) or ``cookie``
  (the callback sets a session cookie and returns no code).
* ``GET  /auth2/callback``  — exchange the IdP code, JIT-provision the user,
  persist the encrypted IdP refresh token, set a session cookie, and redirect
  to the client's redirect URI. For ``response_type=code`` the redirect carries
  our authorization code + the original state; for ``response_type=cookie`` no
  code is returned (the cookie authenticates the browser).
* ``POST /auth2/token``     — exchange our authorization code for an access +
  refresh token pair (RFC 6749 §4.1.3). Also handles the refresh grant.
* ``POST /auth2/refresh``   — rotate the access + refresh pair via the IdP.

OAuth client management is a REST resource at ``/auth2/clients``.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from openhands.ev2.auth2.auth2_models import OAuthClient
from openhands.ev2.auth2.auth2_schemas import (
    OAuthClientCreate,
    OAuthClientRead,
    OAuthClientSearchResult,
    OAuthClientUpdate,
    TokenRequest,
    TokenResponse,
)
from openhands.ev2.auth2.auth2_service import (
    Auth2Error,
    Auth2Service,
    IdpError,
    InvalidClientError,
    InvalidGrantError,
    InvalidRedirectUriError,
)
from openhands.ev2.config import get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.permission.permission_dependencies import require_permission
from openhands.ev2.permission.permission_models import Action, ResourceType
from openhands.ev2.util.search_filter import SearchFilter

router = APIRouter(prefix="/auth2", tags=["auth2"])


def _callback_url() -> str:
    """Derive the absolute callback URL from application config.

    Config-driven (rather than ``request.base_url``) so the URL is correct
    behind K8s ingresses / proxies that rewrite Host or scheme.
    """
    base_url = get_config().base_url.rstrip("/")
    return f"{base_url}/auth2/callback"


def _set_session_cookie(response: RedirectResponse, user_id: uuid.UUID) -> None:
    """Set a JWE session cookie so browser flows authenticate subsequently.

    Reuses the legacy cookie token (mints without a DB session) so the existing
    ``get_current_user_id`` dependency authenticates auth2 sessions unchanged.
    """
    from openhands.ev2.util.auth_token import create_auth_token

    cfg = get_config()
    cookie_token = create_auth_token(user_id)
    response.set_cookie(
        key=cfg.auth_cookie_name,
        value=cookie_token,
        max_age=cfg.auth_cookie_timeout_seconds,
        httponly=True,
        samesite="lax",
        secure=cfg.auth_cookie_secure,
        path="/",
    )


def _error_status(exc: Auth2Error) -> int:
    if isinstance(exc, InvalidClientError):
        return status.HTTP_401_UNAUTHORIZED
    if isinstance(exc, InvalidRedirectUriError):
        return status.HTTP_400_BAD_REQUEST
    if isinstance(exc, InvalidGrantError):
        return status.HTTP_400_BAD_REQUEST
    if isinstance(exc, IdpError):
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_400_BAD_REQUEST


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
      ``/auth2/token``.
    * ``cookie`` — a browser-oriented variant. After the IdP redirects back,
      the callback sets a session cookie and returns **no** code; the browser
      is authenticated by the cookie alone.

    Any other value is rejected by the OpenAPI-declared enum (HTTP 422).
    """
    service = Auth2Service(session)
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
    except Auth2Error as exc:
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
    exchange the code at ``/auth2/token``. For ``response_type=cookie`` no code
    is returned (the redirect carries only the optional ``state``); the session
    cookie authenticates the browser.
    """
    service = Auth2Service(session)
    try:
        ctx = await service.handle_callback(
            code=code,
            state=state,
            callback_url=_callback_url(),
        )
    except Auth2Error as exc:
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
    _set_session_cookie(response, ctx.user_id)
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
    service = Auth2Service(session)
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
    except Auth2Error as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type="Bearer",
        expires_in=pair.expires_in,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: TokenRequest,
    session: SessionDep,
) -> TokenResponse:
    """Rotate the access + refresh pair via the IdP (refresh grant).

    OAuth standard refresh-token grant (RFC 6749 §6): the existing refresh
    token is exchanged at the IdP for a fresh access + refresh pair.
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
    service = Auth2Service(session)
    try:
        pair = await service.exchange_refresh_token(
            refresh_token=payload.refresh_token,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
        )
    except Auth2Error as exc:
        raise HTTPException(status_code=_error_status(exc), detail=str(exc)) from exc
    finally:
        await service.aclose()
    await session.commit()
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type="Bearer",
        expires_in=pair.expires_in,
    )


# ---------------------------------------------------------------------- #
# OAuth clients — REST resource, permission-guarded.
# ---------------------------------------------------------------------- #


async def _to_read(service: Auth2Service, client: OAuthClient) -> OAuthClientRead:
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
        SearchFilter[Any],
        Depends(require_permission(Action.SEARCH, ResourceType.OAUTH_CLIENT)),
    ],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OAuthClientSearchResult:
    """List OAuth clients, scoped to the principal's permission filter."""
    service = Auth2Service(session)
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
        SearchFilter[Any],
        Depends(require_permission(Action.CREATE, ResourceType.OAUTH_CLIENT)),
    ],
) -> OAuthClientRead:
    """Register an OAuth client with an encrypted secret + redirect URIs."""
    service = Auth2Service(session)
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
    return await _to_read(Auth2Service(session), client)


@router.get("/clients/{client_id}", response_model=OAuthClientRead)
async def get_client(
    client_id: uuid.UUID,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[Any],
        Depends(require_permission(Action.READ, ResourceType.OAUTH_CLIENT)),
    ],
) -> OAuthClientRead:
    """Retrieve an OAuth client by id, scoped to the principal."""
    service = Auth2Service(session)
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
        SearchFilter[Any],
        Depends(require_permission(Action.UPDATE, ResourceType.OAUTH_CLIENT)),
    ],
) -> OAuthClientRead:
    """Partially update an OAuth client (rename, re-secret, re-uris, disable)."""
    service = Auth2Service(session)
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
        SearchFilter[Any],
        Depends(require_permission(Action.DELETE, ResourceType.OAUTH_CLIENT)),
    ],
) -> None:
    """Delete an OAuth client by id, scoped to the principal."""
    service = Auth2Service(session)
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
