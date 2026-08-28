"""Built-in dev identity provider mounted at ``/auth/dev``.

Selected by setting ``idp.url = "/auth/dev"`` (the default). This router acts
as a minimal OAuth2 identity provider so the system works out of the box
without configuring an external IdP:

* ``GET  /auth/dev/authorize`` — the browser-facing authorization endpoint. It
  returns ``401`` (with a ``WWW-Authenticate: Basic`` challenge) unless a
  correct ``username`` / ``password`` for an *enabled* user in the database is
  supplied via HTTP Basic auth. On success it mints a short-lived authorization
  code and redirects to the project's OAuth callback with ``code`` + ``state``.
* ``POST /auth/dev/token``     — exchanges the authorization code (or rotates a
  refresh token) for an IdP access + refresh token pair plus an ``id_token``
  carrying ``sub`` (the local user id) and ``email``. The project's
  :class:`~openhands.ev2.auth.auth_service.AuthService` consumes this response
  exactly as it would a real IdP's, so the federated flow is reused unchanged.
* ``POST /auth/dev/refresh``   — the dedicated refresh endpoint (also accepted
  at ``/auth/dev/token`` via ``grant_type=refresh_token`` because the IdP token
  path defaults to ``/token``).

Access and refresh token lifetimes are taken from :class:`IdpConfig`
(``access_token_expires_in`` / ``refresh_token_expires_in``). The minted tokens
are opaque JWEs; only this dev IdP needs to decrypt them. It is **not** a
production IdP — it exists so users can try the system before wiring up a real
identity provider.
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_service import _derive_code_challenge, _join_url
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.db import SessionDep
from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.user.user_models import User
from openhands.ev2.util.password import verify_password

# JWE claim keys (kept private to the dev IdP).
_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"
_JTI_CLAIM = "jti"
_EXP_CLAIM = "exp"
_EMAIL_CLAIM = "email"
_CLIENT_ID_CLAIM = "cid"
_REDIRECT_URI_CLAIM = "ruri"
_CODE_CHALLENGE_CLAIM = "cc"
_CODE_METHOD_CLAIM = "ccm"
_STATE_CLAIM = "st"

_DEV_CODE_TYP = "dev_authorization_code"
_DEV_ACCESS_TYP = "dev_access_token"
_DEV_REFRESH_TYP = "dev_refresh_token"

# Lifetime of the short-lived authorization code minted at /authorize.
_DEV_CODE_TTL = timedelta(minutes=10)

_basic_scheme = HTTPBasic(auto_error=False, scheme_name="DevIdpBasic")


class DevIdpError(Exception):
    """Base class for dev IdP domain errors."""


class InvalidClientError(DevIdpError):
    """The client_id / client_secret pair does not match the configured IdP client."""


class InvalidGrantError(DevIdpError):
    """The authorization code or refresh token is invalid / expired / revoked."""


class InvalidRedirectUriError(DevIdpError):
    """The redirect_uri does not match the project's OAuth callback URL."""


def _now() -> datetime:
    return datetime.now(UTC)


def _seconds_until(expires_at: datetime) -> int:
    return max(0, int((expires_at - _now()).total_seconds()))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_id_token(sub: str, email: str) -> str:
    """Build an unsigned (``alg=none``) id_token carrying ``sub`` + ``email``.

    The project's AuthService decodes the id_token without verifying its
    signature (verification is the IdP's job during the real exchange), so an
    unsigned JWT is sufficient for the dev provider. ``sub`` is the local user
    id so the callback's JIT provisioning links the IdP subject to the user.
    """
    header = _b64url(json.dumps({"alg": "none"}).encode())
    payload = _b64url(json.dumps({"sub": sub, "email": email}).encode())
    return f"{header}.{payload}."


class DevIdpService:
    """Issue, exchange, and rotate the dev IdP's OAuth tokens.

    Constructed per request with the request-scoped session. The encryption
    service and config are injectable for tests. Tokens are self-contained
    JWEs (no DB rows): the code carries the user identity + PKCE challenge, and
    the refresh token carries the user id so ``/refresh`` can mint a successor
    pair without re-authenticating.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        encryption_service: EncryptionService | None = None,
        config: AppConfig | None = None,
    ) -> None:
        self._session = session
        self._enc = encryption_service or get_encryption_service()
        self._cfg = config or get_config()
        self._idp = self._cfg.idp

    # ------------------------------------------------------------------ #
    # /authorize — authenticate the user, mint the authorization code.
    # ------------------------------------------------------------------ #

    async def authorize(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        username: str,
        password: str,
    ) -> str:
        """Validate the client + user and return the callback redirect URL.

        Raises :class:`InvalidClientError` / :class:`InvalidRedirectUriError` /
        :class:`InvalidGrantError` (bad credentials / disabled user).
        """
        self._validate_client(client_id, None)
        self._validate_redirect_uri(redirect_uri)
        user = await self._authenticate_user(username, password)

        code = self._mint_code(
            user_id=user.id,
            email=user.email,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        params: dict[str, str] = {"code": code}
        if state is not None:
            params["state"] = state
        return _join_url(redirect_uri, "", params)

    # ------------------------------------------------------------------ #
    # /token — exchange the code (or refresh) for an IdP token pair.
    # ------------------------------------------------------------------ #

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        """Exchange an authorization code for an IdP access + refresh pair.

        Validates the client secret, the redirect_uri match, and PKCE. Raises
        :class:`InvalidClientError` / :class:`InvalidGrantError`.
        """
        self._validate_client(client_id, client_secret)
        payload = self._decrypt(code)
        if payload.get(_TYP_CLAIM) != _DEV_CODE_TYP:
            raise InvalidGrantError("not an authorization code")
        if payload.get(_REDIRECT_URI_CLAIM) != redirect_uri:
            raise InvalidGrantError("redirect_uri mismatch")
        self._verify_pkce(
            challenge=payload.get(_CODE_CHALLENGE_CLAIM),
            method=payload.get(_CODE_METHOD_CLAIM),
            verifier=code_verifier,
        )
        user_id = self._user_id(payload)
        email = self._email(payload)
        return self._token_response(user_id, email)

    async def refresh(
        self,
        *,
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> dict[str, Any]:
        """Rotate the IdP access + refresh pair from a refresh token."""
        self._validate_client(client_id, client_secret)
        payload = self._decrypt(refresh_token)
        if payload.get(_TYP_CLAIM) != _DEV_REFRESH_TYP:
            raise InvalidGrantError("not a refresh token")
        user_id = self._user_id(payload)
        email = self._email(payload)
        return self._token_response(user_id, email)

    # ------------------------------------------------------------------ #
    # Internals — validation.
    # ------------------------------------------------------------------ #

    def _validate_client(self, client_id: str, client_secret: str | None) -> None:
        """Validate the client_id (and secret, when supplied) against IdPConfig."""
        if not secrets.compare_digest(client_id, self._idp.client_id):
            raise InvalidClientError(client_id)
        if client_secret is not None and not secrets.compare_digest(
            client_secret, self._idp.client_secret.get_secret_value()
        ):
            raise InvalidClientError(client_id)

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        """Ensure the redirect_uri is the project's own OAuth callback URL."""
        expected = f"{self._cfg.base_url.rstrip('/')}/auth/callback"
        if redirect_uri != expected:
            raise InvalidRedirectUriError(redirect_uri)

    async def _authenticate_user(self, username: str, password: str) -> User:
        """Load the user by username and verify the password + enabled flag."""
        result = await self._session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user is None or not user.enabled or not user.password:
            raise InvalidGrantError("invalid credentials")
        if not verify_password(password, user.password):
            raise InvalidGrantError("invalid credentials")
        return user

    def _verify_pkce(
        self,
        *,
        challenge: Any,
        method: Any,
        verifier: str | None,
    ) -> None:
        if challenge is None:
            return
        if verifier is None:
            raise InvalidGrantError("missing code_verifier")
        m = method or "plain"
        expected = _derive_code_challenge(verifier, m)
        if not secrets.compare_digest(expected, str(challenge)):
            raise InvalidGrantError("PKCE verification failed")

    # ------------------------------------------------------------------ #
    # Internals — token minting.
    # ------------------------------------------------------------------ #

    def _token_response(self, user_id: uuid.UUID, email: str) -> dict[str, Any]:
        """Mint a fresh IdP access + refresh pair and id_token (RFC 6749 §5.1)."""
        access_ttl = timedelta(seconds=max(1, self._idp.access_token_expires_in))
        refresh_ttl = timedelta(seconds=max(1, self._idp.refresh_token_expires_in))
        access_exp = _now() + access_ttl
        refresh_exp = _now() + refresh_ttl
        access = self._mint(_DEV_ACCESS_TYP, user_id, access_ttl)
        # The refresh token carries the user id + email so /refresh can mint a
        # successor pair (with a fresh id_token) without re-authenticating or
        # re-reading the user from the database.
        refresh = self._mint(_DEV_REFRESH_TYP, user_id, refresh_ttl, email=email)
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": _seconds_until(access_exp),
            "refresh_expires_in": _seconds_until(refresh_exp),
            "id_token": _make_id_token(str(user_id), email),
        }

    def _mint(
        self,
        token_type: str,
        user_id: uuid.UUID,
        expires_in: timedelta,
        *,
        email: str | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: token_type,
            _JTI_CLAIM: str(uuid.uuid4()),
        }
        if email is not None:
            claims[_EMAIL_CLAIM] = email
        return self._enc.create_jwe_token(claims, expires_in=expires_in)

    def _mint_code(
        self,
        *,
        user_id: uuid.UUID,
        email: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> str:
        payload: dict[str, Any] = {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: _DEV_CODE_TYP,
            _JTI_CLAIM: str(uuid.uuid4()),
            _EMAIL_CLAIM: email,
            _CLIENT_ID_CLAIM: client_id,
            _REDIRECT_URI_CLAIM: redirect_uri,
        }
        if code_challenge is not None:
            payload[_CODE_CHALLENGE_CLAIM] = code_challenge
            payload[_CODE_METHOD_CLAIM] = code_challenge_method or "plain"
        return self._enc.create_jwe_token(payload, expires_in=_DEV_CODE_TTL)

    def _decrypt(self, token: str) -> dict[str, Any]:
        try:
            payload = self._enc.decrypt_jwe_token(token)
        except Exception as exc:
            raise InvalidGrantError("token decryption failed") from exc
        if not isinstance(payload, dict):
            raise InvalidGrantError("invalid token payload")
        return payload

    def _user_id(self, payload: dict[str, Any]) -> uuid.UUID:
        raw = payload.get(_SUB_CLAIM)
        if not isinstance(raw, str):
            raise InvalidGrantError("missing subject")
        try:
            return uuid.UUID(raw)
        except ValueError as exc:
            raise InvalidGrantError("invalid subject") from exc

    def _email(self, payload: dict[str, Any]) -> str:
        raw = payload.get(_EMAIL_CLAIM)
        if not isinstance(raw, str) or not raw:
            raise InvalidGrantError("missing email")
        return raw


router = APIRouter(prefix="/auth/dev", tags=["auth-dev"])


def _basic_auth_unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing dev IdP credentials.",
        headers={"WWW-Authenticate": 'Basic realm="ohe-dev-idp"'},
    )


async def _dev_idp_dep(
    session: SessionDep,
) -> DevIdpService:
    """Build a per-request DevIdpService (no owned resources to close)."""
    return DevIdpService(session)


DevIdpDep = Annotated[DevIdpService, Depends(_dev_idp_dep)]


@router.get("/authorize")
async def authorize(
    service: DevIdpDep,
    response_type: Annotated[str, Query()],
    client_id: Annotated[str, Query()],
    redirect_uri: Annotated[str, Query()],
    state: Annotated[str | None, Query()] = None,
    scope: Annotated[str | None, Query()] = None,
    code_challenge: Annotated[str | None, Query()] = None,
    code_challenge_method: Annotated[str | None, Query()] = None,
    credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic_scheme)] = None,
) -> RedirectResponse:
    """Dev IdP authorization endpoint.

    Returns ``401`` (Basic auth challenge) unless a valid username + password
    for an enabled user is supplied via HTTP Basic auth. On success, mints an
    authorization code and redirects to the project's OAuth callback.
    """
    _ = scope  # accepted but ignored (dev IdP grants ``openid email profile``)
    if credentials is None:
        raise _basic_auth_unauthorized()
    try:
        location = await service.authorize(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            username=credentials.username,
            password=credentials.password,
        )
    except InvalidClientError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except InvalidRedirectUriError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except InvalidGrantError:
        raise _basic_auth_unauthorized() from None
    return RedirectResponse(url=location, status_code=status.HTTP_302_FOUND)


@router.post("/token")
async def token(
    service: DevIdpDep,
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
) -> dict[str, Any]:
    """Dev IdP token endpoint (RFC 6749 §4.1.3 + §6).

    Accepts form-encoded bodies (``grant_type`` of ``authorization_code`` or
    ``refresh_token``). Returns the IdP token response consumed by the
    project's AuthService.
    """
    return await _handle_token(
        service,
        grant_type=grant_type,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        code_verifier=code_verifier,
        refresh_token=refresh_token,
    )


@router.post("/refresh")
async def refresh(
    service: DevIdpDep,
    grant_type: Annotated[str, Form()] = "refresh_token",
    refresh_token: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
) -> dict[str, Any]:
    """Dev IdP refresh endpoint — the refresh grant as a dedicated route."""
    if grant_type != "refresh_token":
        grant_type = "refresh_token"
    return await _handle_token(
        service,
        grant_type=grant_type,
        code=None,
        redirect_uri=None,
        client_id=client_id,
        client_secret=client_secret,
        code_verifier=None,
        refresh_token=refresh_token,
    )


async def _handle_token(
    service: DevIdpService,
    *,
    grant_type: str,
    code: str | None,
    redirect_uri: str | None,
    client_id: str | None,
    client_secret: str | None,
    code_verifier: str | None,
    refresh_token: str | None,
) -> dict[str, Any]:
    try:
        if grant_type == "authorization_code":
            if code is None or redirect_uri is None or client_id is None or client_secret is None:
                raise InvalidGrantError("missing authorization_code parameters")
            return await service.exchange_code(
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
                code_verifier=code_verifier,
            )
        if grant_type == "refresh_token":
            if refresh_token is None or client_id is None or client_secret is None:
                raise InvalidGrantError("missing refresh_token parameters")
            return await service.refresh(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
            )
        raise InvalidGrantError("grant_type must be 'authorization_code' or 'refresh_token'")
    except InvalidClientError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except InvalidGrantError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except InvalidRedirectUriError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


__all__ = ["DevIdpService", "router"]
