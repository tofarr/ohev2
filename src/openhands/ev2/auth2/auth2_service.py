"""Service layer for the federated OAuth (auth2) feature.

The project acts as a federated OAuth proxy:

1. ``/auth2/authorize`` validates the client + redirect URI, then redirects the
   browser to the IdP authorization endpoint. A short-lived signed "pending
   auth" JWE is carried as the IdP ``state`` so the callback can recover the
   client context (client id, redirect uri, client state, PKCE challenge).
2. ``/auth2/callback`` exchanges the IdP code for IdP tokens, extracts the
   user identity from the id_token (or refresh-token JWT), JIT-provisions or
   looks up the local user, persists the encrypted IdP refresh token, and
   mints a short-lived authorization code (JWE) that the client exchanges at
   ``/auth2/token``. A session cookie is also set so browser flows work without
   a second round trip.
3. ``/auth2/token`` exchanges the authorization code for our access + refresh
   tokens, validating PKCE and the client secret.
4. ``/auth2/refresh`` rotates the access + refresh pair by refreshing the IdP
   refresh token and re-persisting it.

Access tokens are self-contained JWEs (``ttyp: access_token``) so the existing
:func:`get_current_user_id` dependency authenticates them unchanged. Refresh
tokens are JWEs (``ttyp: idp_refresh_token``) carrying the ``idp_refresh_tokens``
row id; only the auth2 refresh endpoint accepts them.

All IdP HTTP calls go through :class:`httpx.AsyncClient`; tests inject a mock
transport. Sensitive values (IdP refresh token, client secret) are encrypted at
rest via the encryption service (AGENTS.md §9).
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import TokenType
from openhands.ev2.auth2.auth2_models import (
    IdpRefreshToken,
    OAuthClient,
    OAuthClientAllowedOrigin,
    OAuthClientRedirectUri,
)
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.encryption.encryption_service import (
    EncryptionService,
    get_encryption_service,
)
from openhands.ev2.user.user_models import User

# JWT claim keys reused from the auth service for token-type tagging.
_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"
_JTI_CLAIM = "jti"
_EXP_CLAIM = "exp"
_IAT_CLAIM = "iat"

# Custom claims carried in the pending-auth and authorization-code JWEs.
_CLIENT_ID_CLAIM = "cid"
_REDIRECT_URI_CLAIM = "ruri"
_STATE_CLAIM = "st"
_CODE_CHALLENGE_CLAIM = "cc"
_CODE_METHOD_CLAIM = "ccm"
_ROW_ID_CLAIM = "rid"
_RESPONSE_TYPE_CLAIM = "rtyp"

# Supported response_type values for the provider-facing authorize request.
# The IdP flow is always a code flow (the project is the OAuth client to the
# IdP); this value only governs what the callback returns to the first-party
# client — an exchangeable code, or a session cookie with no code.
_RESPONSE_TYPE_CODE = "code"
_RESPONSE_TYPE_COOKIE = "cookie"
_RESPONSE_TYPES = (_RESPONSE_TYPE_CODE, _RESPONSE_TYPE_COOKIE)

# Default lifetime of the authorization code minted at callback (10 minutes).
_AUTH_CODE_TTL = timedelta(minutes=10)
# Lifetime of the pending-auth JWE carried as IdP state (10 minutes).
_PENDING_AUTH_TTL = timedelta(minutes=10)


class Auth2Error(Exception):
    """Base class for auth2 domain errors."""


class InvalidClientError(Auth2Error):
    """The client_id / client_secret pair is unknown or disabled."""


class InvalidRedirectUriError(Auth2Error):
    """The redirect_uri is not permitted for the client."""


class InvalidOriginError(Auth2Error):
    """The browser origin is not permitted for the client's cookie flow."""


class InvalidGrantError(Auth2Error):
    """The authorization code or refresh token is invalid/expired/revoked."""


class IdpError(Auth2Error):
    """The identity provider returned an error or an unusable response."""


def _now() -> datetime:
    return datetime.now(UTC)


class Auth2Service:
    """Issue, exchange, and rotate federated OAuth tokens.

    Constructed per request with the request-scoped session. The IdP HTTP
    client and encryption service are injectable for tests.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        http_client: httpx.AsyncClient | None = None,
        encryption_service: EncryptionService | None = None,
        config: AppConfig | None = None,
    ) -> None:
        self._session = session
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._enc = encryption_service or get_encryption_service()
        self._cfg = config or get_config()

    async def aclose(self) -> None:
        """Close the IdP HTTP client if this service owns it."""
        if self._owns_client:
            await self._http.aclose()

    # ------------------------------------------------------------------ #
    # /authorize — build the IdP redirect URL.
    # ------------------------------------------------------------------ #

    async def build_authorize_redirect(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str | None,
        scope: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        callback_url: str,
        response_type: str = _RESPONSE_TYPE_CODE,
        origin: str | None = None,
    ) -> str:
        """Validate the client + redirect URI and return the IdP authorize URL.

        *response_type* is the provider-facing value (``code`` or ``cookie``)
        recorded in the pending-auth state so the callback knows whether to
        mint an exchangeable code (``code``) or only set a session cookie
        (``cookie``). The IdP request itself is always a code flow.

        For the ``cookie`` response type, *origin* (the browser origin of the
        page initiating the flow) is checked against the client's configured
        allowed origins when that list is non-empty — an XSRF defense so a
        cookie flow can only be started from a trusted site.

        Raises :class:`InvalidClientError` / :class:`InvalidRedirectUriError`
        / :class:`InvalidOriginError`.
        """
        if response_type not in _RESPONSE_TYPES:
            raise Auth2Error(f"response_type must be one of {_RESPONSE_TYPES}")
        client = await self._load_client(client_id)
        if not await self._redirect_uri_allowed(client, redirect_uri):
            raise InvalidRedirectUriError(redirect_uri)
        if response_type == _RESPONSE_TYPE_COOKIE:
            await self._enforce_origin(client, origin)

        # PKCE verifier the project uses against the IdP. The client's own
        # challenge (if any) is recorded in the pending-auth state so /token
        # can verify it.
        verifier = _generate_code_verifier()
        idp_challenge = _derive_code_challenge(verifier, "S256")
        idp_state = self._mint_pending_auth(
            client_id=client_id,
            redirect_uri=redirect_uri,
            client_state=state,
            scope=scope,
            client_code_challenge=code_challenge,
            client_code_method=code_challenge_method,
            idp_verifier=verifier,
            response_type=response_type,
        )

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._cfg.idp_client_id,
            "redirect_uri": callback_url,
            "state": idp_state,
            "scope": " ".join(self._cfg.idp_scopes),
            "code_challenge": idp_challenge,
            "code_challenge_method": "S256",
        }
        return _join_url(self._cfg.idp_url, self._cfg.idp_authorize_path, params)

    # ------------------------------------------------------------------ #
    # /callback — exchange the IdP code, provision the user, mint our code.
    # ------------------------------------------------------------------ #

    async def handle_callback(
        self,
        *,
        code: str,
        state: str,
        callback_url: str,
    ) -> CallbackContext:
        """Exchange the IdP code and return the context for the client redirect.

        For the ``code`` response type an exchangeable authorization code is
        minted; for the ``cookie`` response type ``auth_code`` is ``None`` and
        the caller is expected to authenticate the browser via the session
        cookie alone. Raises :class:`InvalidGrantError` (bad state) or
        :class:`IdpError`.
        """
        pending = self._decode_pending_auth(state)
        idp_tokens = await self._exchange_code_with_idp(
            code=code,
            verifier=pending["idp_verifier"],
            callback_url=callback_url,
        )
        user = await self._provision_user(idp_tokens)
        row = await self._persist_idp_refresh(user.id, idp_tokens)

        response_type = pending["response_type"]
        auth_code: str | None = None
        if response_type == _RESPONSE_TYPE_CODE:
            auth_code = self._mint_auth_code(
                user_id=user.id,
                row_id=row.id,
                client_id=pending["client_id"],
                redirect_uri=pending["redirect_uri"],
                client_code_challenge=pending["client_code_challenge"],
                client_code_method=pending["client_code_method"],
            )
        return CallbackContext(
            user_id=user.id,
            row_id=row.id,
            client_id=pending["client_id"],
            redirect_uri=pending["redirect_uri"],
            client_state=pending["client_state"],
            response_type=response_type,
            auth_code=auth_code,
            expires_in=self._access_ttl_seconds(),
        )

    # ------------------------------------------------------------------ #
    # /token — exchange our authorization code for access + refresh tokens.
    # ------------------------------------------------------------------ #

    async def exchange_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        code_verifier: str | None,
    ) -> TokenPair:
        """Exchange our auth code for an access + refresh token pair.

        Validates the client secret, the redirect_uri match, and PKCE. Raises
        :class:`InvalidClientError` / :class:`InvalidGrantError`.
        """
        client = await self._authenticate_client(client_id, client_secret)
        _ = client  # validated; redirect_uri is checked against the code
        payload = self._decrypt(code)
        if payload.get(_TYP_CLAIM) != _AUTH_CODE_TYP:
            raise InvalidGrantError("not an authorization code")
        if payload.get(_REDIRECT_URI_CLAIM) != redirect_uri:
            raise InvalidGrantError("redirect_uri mismatch")
        self._verify_pkce(
            challenge=payload.get(_CODE_CHALLENGE_CLAIM),
            method=payload.get(_CODE_METHOD_CLAIM),
            verifier=code_verifier,
        )
        user_id = _uuid(payload, _SUB_CLAIM)
        row_id = _uuid(payload, _ROW_ID_CLAIM)
        row = await self._load_refresh_row(row_id)
        if row is None or row.user_id != user_id:
            raise InvalidGrantError("stale authorization code")
        return await self._mint_token_pair(user_id, row)

    # ------------------------------------------------------------------ #
    # /refresh — rotate the access + refresh pair via the IdP.
    # ------------------------------------------------------------------ #

    async def exchange_refresh_token(
        self,
        *,
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> TokenPair:
        """Rotate the access + refresh pair by refreshing the IdP token.

        Raises :class:`InvalidClientError` / :class:`InvalidGrantError` /
        :class:`IdpError`.
        """
        await self._authenticate_client(client_id, client_secret)
        payload = self._decrypt(refresh_token)
        if self._token_type(payload) is not TokenType.IDP_REFRESH_TOKEN:
            raise InvalidGrantError("not a refresh token")
        row_id = _uuid(payload, _ROW_ID_CLAIM)
        user_id = _uuid(payload, _SUB_CLAIM)
        row = await self._load_refresh_row(row_id)
        if row is None or row.user_id != user_id:
            raise InvalidGrantError("refresh token not recognized")
        if row.expires_at <= _now():
            raise InvalidGrantError("refresh token expired")

        idp_refresh = self._enc.decrypt_value(row.refresh_token)
        idp_tokens = await self._refresh_with_idp(idp_refresh)
        # Update the row with the new IdP refresh token (if the IdP rotated it)
        # and its expiry.
        new_idp_refresh = idp_tokens.get("refresh_token") or idp_refresh
        row.refresh_token = self._enc.encrypt_value(new_idp_refresh)
        row.expires_at = _idp_expiry(idp_tokens, self._cfg.idp_expire_drift_tolerance)
        await self._session.flush()
        return await self._mint_token_pair(user_id, row)

    # ------------------------------------------------------------------ #
    # Background cleanup of expired IdP refresh tokens.
    # ------------------------------------------------------------------ #

    async def delete_expired_tokens(self) -> int:
        """Delete expired IdP refresh tokens older than the configured age.

        Rows whose ``expires_at`` is in the past and older than
        ``idp_delete_expired_seconds`` (measured from now) are removed. Returns
        the number of rows deleted.
        """
        cutoff = _now() - timedelta(seconds=self._cfg.idp_delete_expired_seconds)
        from sqlalchemy import CursorResult

        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                delete(IdpRefreshToken).where(IdpRefreshToken.expires_at < cutoff)
            ),
        )
        await self._session.commit()
        return result.rowcount or 0

    # ------------------------------------------------------------------ #
    # OAuth client management (CRUD helpers used by the router).
    # ------------------------------------------------------------------ #

    async def create_client(
        self,
        *,
        client_id: str,
        client_secret: str,
        name: str | None,
        redirect_uris: list[str],
        allowed_origins: list[str],
        enabled: bool,
    ) -> OAuthClient:
        """Create an OAuth client with an encrypted secret and redirect URIs."""
        client = OAuthClient(
            client_id=client_id,
            client_secret=self._enc.encrypt_value(client_secret),
            name=name,
            enabled=enabled,
        )
        self._session.add(client)
        await self._session.flush()
        for uri in redirect_uris:
            self._session.add(OAuthClientRedirectUri(client_id=client.id, uri=uri))
        for origin in allowed_origins:
            self._session.add(OAuthClientAllowedOrigin(client_id=client.id, origin=origin))
        await self._session.flush()
        await self._session.refresh(client)
        return client

    async def list_redirect_uris(self, client: OAuthClient) -> list[str]:
        """Return the redirect URIs registered for *client*."""
        result = await self._session.execute(
            select(OAuthClientRedirectUri.uri)
            .where(OAuthClientRedirectUri.client_id == client.id)
            .order_by(OAuthClientRedirectUri.uri)
        )
        return list(result.scalars().all())

    async def replace_redirect_uris(
        self,
        client: OAuthClient,
        uris: list[str],
    ) -> None:
        """Replace a client's redirect URIs."""
        await self._session.execute(
            delete(OAuthClientRedirectUri).where(OAuthClientRedirectUri.client_id == client.id)
        )
        for uri in uris:
            self._session.add(OAuthClientRedirectUri(client_id=client.id, uri=uri))
        await self._session.flush()

    async def list_allowed_origins(self, client: OAuthClient) -> list[str]:
        """Return the allowed browser origins registered for *client*."""
        result = await self._session.execute(
            select(OAuthClientAllowedOrigin.origin)
            .where(OAuthClientAllowedOrigin.client_id == client.id)
            .order_by(OAuthClientAllowedOrigin.origin)
        )
        return list(result.scalars().all())

    async def replace_allowed_origins(
        self,
        client: OAuthClient,
        origins: list[str],
    ) -> None:
        """Replace a client's allowed browser origins (XSRF allow-list)."""
        await self._session.execute(
            delete(OAuthClientAllowedOrigin).where(OAuthClientAllowedOrigin.client_id == client.id)
        )
        for origin in origins:
            self._session.add(OAuthClientAllowedOrigin(client_id=client.id, origin=origin))
        await self._session.flush()

    async def get_client(self, client_id: uuid.UUID) -> OAuthClient | None:
        """Load an OAuth client by its primary key."""
        return await self._session.get(OAuthClient, client_id)

    async def get_client_by_client_id(self, client_id: str) -> OAuthClient | None:
        """Load an OAuth client by its public client_id."""
        result = await self._session.execute(
            select(OAuthClient).where(OAuthClient.client_id == client_id)
        )
        return result.scalar_one_or_none()

    async def search_clients(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[OAuthClient], uuid.UUID | None]:
        """Search OAuth clients ordered by id, keyed pagination.

        Fetches ``limit + 1`` rows to detect whether another page exists; the
        cursor is the id of the last returned row, or ``None`` if this is the
        final page.
        """
        stmt = select(OAuthClient).order_by(OAuthClient.id)
        if cursor is not None:
            stmt = stmt.where(OAuthClient.id > cursor)
        stmt = stmt.limit(limit + 1)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        if len(rows) <= limit:
            return rows, None
        return rows[:limit], rows[limit - 1].id

    async def delete_client(self, client: OAuthClient) -> None:
        """Delete an OAuth client (cascades to redirect URIs)."""
        await self._session.delete(client)
        await self._session.flush()

    # ------------------------------------------------------------------ #
    # Internals — IdP HTTP.
    # ------------------------------------------------------------------ #

    async def _exchange_code_with_idp(
        self,
        *,
        code: str,
        verifier: str,
        callback_url: str,
    ) -> dict[str, Any]:
        """Exchange an authorization code for IdP tokens (RFC 6749 §4.1.3)."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": self._cfg.idp_client_id,
            "client_secret": self._cfg.idp_client_secret.get_secret_value(),
            "code_verifier": verifier,
        }
        return await self._idp_token_post(data)

    async def _refresh_with_idp(self, refresh_token: str) -> dict[str, Any]:
        """Refresh the IdP access token using a refresh token (RFC 6749 §6)."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._cfg.idp_client_id,
            "client_secret": self._cfg.idp_client_secret.get_secret_value(),
        }
        return await self._idp_token_post(data)

    async def _idp_token_post(self, data: dict[str, str]) -> dict[str, Any]:
        url = _join_url(self._cfg.idp_url, self._cfg.idp_token_path)
        try:
            resp = await self._http.post(url, data=data)
        except httpx.HTTPError as exc:
            raise IdpError(f"IdP token endpoint unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise IdpError(f"IdP token endpoint returned {resp.status_code}")
        body = cast("dict[str, Any]", resp.json())
        if "access_token" not in body:
            raise IdpError("IdP token response missing access_token")
        return body

    # ------------------------------------------------------------------ #
    # Internals — user provisioning.
    # ------------------------------------------------------------------ #

    async def _provision_user(self, idp_tokens: dict[str, Any]) -> User:
        """Look up or JIT-create the local user from IdP token claims.

        The stable IdP subject (``idp_user_id_field`` or ``sub``) is the
        primary key for lookup; email (``idp_email_field`` or ``email``) is the
        fallback for first-time provisioning. Raises :class:`IdpError` if no
        usable identity claim is present.
        """
        id_token = idp_tokens.get("id_token")
        claims = _decode_id_token(id_token) if id_token else {}
        idp_user_id = _claim(claims, self._cfg.idp_user_id_field, "sub")
        email = _claim(claims, self._cfg.idp_email_field, "email")

        if idp_user_id is not None:
            user = await self._find_user_by_idp_id(idp_user_id)
            if user is not None:
                return user
        if email is not None:
            user = await self._find_user_by_email(email)
            if user is not None:
                # Link the IdP subject to the existing local user.
                if idp_user_id is not None and user.idp_user_id is None:
                    user.idp_user_id = idp_user_id
                    await self._session.flush()
                return user
        if idp_user_id is None and email is None:
            raise IdpError("IdP token carried no usable subject or email claim")

        # JIT provision. Username derives from the email local-part or the IdP
        # subject; uniqueness is enforced by a suffix if needed.
        username = await self._unique_username(email or f"idp-{idp_user_id}")
        user = User(
            email=email or f"{idp_user_id}@idp.local",
            username=username,
            enabled=True,
            idp_user_id=idp_user_id,
        )
        self._session.add(user)
        await self._session.flush()
        await self._session.refresh(user)
        return user

    async def _unique_username(self, base: str) -> str:
        """Return a username derived from *base* that is unique in the DB."""
        local = base.split("@", 1)[0][:60] or "user"
        candidate = local
        suffix = 0
        while True:
            existing = await self._session.execute(select(User).where(User.username == candidate))
            if existing.scalar_one_or_none() is None:
                return candidate
            suffix += 1
            candidate = f"{local}-{suffix}"

    async def _find_user_by_idp_id(self, idp_user_id: str) -> User | None:
        result = await self._session.execute(select(User).where(User.idp_user_id == idp_user_id))
        return result.scalar_one_or_none()

    async def _find_user_by_email(self, email: str) -> User | None:
        result = await self._session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def _persist_idp_refresh(
        self,
        user_id: uuid.UUID,
        idp_tokens: dict[str, Any],
    ) -> IdpRefreshToken:
        """Encrypt and persist the IdP refresh token for *user_id*."""
        refresh = idp_tokens.get("refresh_token")
        if not refresh:
            raise IdpError("IdP token response missing refresh_token")
        row = IdpRefreshToken(
            user_id=user_id,
            refresh_token=self._enc.encrypt_value(refresh),
            expires_at=_idp_expiry(idp_tokens, self._cfg.idp_expire_drift_tolerance),
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)
        return row

    # ------------------------------------------------------------------ #
    # Internals — token minting.
    # ------------------------------------------------------------------ #

    async def _mint_token_pair(
        self,
        user_id: uuid.UUID,
        row: IdpRefreshToken,
    ) -> TokenPair:
        """Mint an access token + refresh token pair for the user/row."""
        access = self._mint_access_token(user_id, row.expires_at)
        refresh = self._mint_refresh_token(user_id, row.id)
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=self._access_ttl_seconds(),
        )

    def _mint_access_token(self, user_id: uuid.UUID, row_expires_at: datetime) -> str:
        """Mint a self-contained access token (``ttyp: access_token``).

        Its expiry is the smaller of the configured access TTL and the IdP
        refresh-token row expiry (minus drift), so an access token never
        outlives the refresh that backs it.
        """
        ttl = timedelta(seconds=self._access_ttl_seconds())
        cap = row_expires_at - _now()
        if cap < ttl:
            ttl = cap
        if ttl.total_seconds() <= 0:
            # The backing refresh token has expired; mint nothing usable.
            ttl = timedelta(seconds=1)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.ACCESS_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
            },
            expires_in=ttl,
        )

    def _mint_refresh_token(self, user_id: uuid.UUID, row_id: uuid.UUID) -> str:
        """Mint a refresh token (``ttyp: idp_refresh_token``) carrying the row id."""
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.IDP_REFRESH_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ROW_ID_CLAIM: str(row_id),
            },
            # Refresh tokens are validated against the row expiry, not the JWE
            # exp; set a long exp so the JWE itself does not pre-expire.
            expires_in=timedelta(days=365),
        )

    def _mint_auth_code(
        self,
        *,
        user_id: uuid.UUID,
        row_id: uuid.UUID,
        client_id: str,
        redirect_uri: str,
        client_code_challenge: str | None,
        client_code_method: str | None,
    ) -> str:
        """Mint a short-lived authorization code (JWE) for the client."""
        payload: dict[str, Any] = {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: _AUTH_CODE_TYP,
            _JTI_CLAIM: str(uuid.uuid4()),
            _ROW_ID_CLAIM: str(row_id),
            _CLIENT_ID_CLAIM: client_id,
            _REDIRECT_URI_CLAIM: redirect_uri,
        }
        if client_code_challenge is not None:
            payload[_CODE_CHALLENGE_CLAIM] = client_code_challenge
            payload[_CODE_METHOD_CLAIM] = client_code_method or "plain"
        return self._enc.create_jwe_token(payload, expires_in=_AUTH_CODE_TTL)

    def _mint_pending_auth(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        client_state: str | None,
        scope: str | None,
        client_code_challenge: str | None,
        client_code_method: str | None,
        idp_verifier: str,
        response_type: str,
    ) -> str:
        """Mint the signed state carrying client context across the IdP redirect."""
        payload: dict[str, Any] = {
            _CLIENT_ID_CLAIM: client_id,
            _REDIRECT_URI_CLAIM: redirect_uri,
            _RESPONSE_TYPE_CLAIM: response_type,
            "ivf": idp_verifier,
        }
        if client_state is not None:
            payload[_STATE_CLAIM] = client_state
        if scope is not None:
            payload["scp"] = scope
        if client_code_challenge is not None:
            payload[_CODE_CHALLENGE_CLAIM] = client_code_challenge
            payload[_CODE_METHOD_CLAIM] = client_code_method or "plain"
        return self._enc.create_jwe_token(payload, expires_in=_PENDING_AUTH_TTL)

    def _decode_pending_auth(self, state: str) -> dict[str, Any]:
        payload = self._decrypt(state)
        if payload.get("ivf") is None or payload.get(_CLIENT_ID_CLAIM) is None:
            raise InvalidGrantError("invalid state")
        # Older pending-auth tokens predate the response_type claim; treat them
        # as the standard code flow so a rolling deploy does not reject in-flight
        # authorizations.
        response_type = payload.get(_RESPONSE_TYPE_CLAIM) or _RESPONSE_TYPE_CODE
        return {
            "client_id": str(payload[_CLIENT_ID_CLAIM]),
            "redirect_uri": str(payload[_REDIRECT_URI_CLAIM]),
            "client_state": payload.get(_STATE_CLAIM),
            "client_code_challenge": payload.get(_CODE_CHALLENGE_CLAIM),
            "client_code_method": payload.get(_CODE_METHOD_CLAIM),
            "response_type": response_type,
            "idp_verifier": str(payload["ivf"]),
        }

    # ------------------------------------------------------------------ #
    # Internals — client / redirect_uri validation.
    # ------------------------------------------------------------------ #

    async def _load_client(self, client_id: str) -> OAuthClient:
        client = await self.get_client_by_client_id(client_id)
        if client is None or not client.enabled:
            raise InvalidClientError(client_id)
        return client

    async def _authenticate_client(
        self,
        client_id: str,
        client_secret: str,
    ) -> OAuthClient:
        """Validate client_id + client_secret. Raises :class:`InvalidClientError`."""
        client = await self.get_client_by_client_id(client_id)
        if client is None or not client.enabled:
            raise InvalidClientError(client_id)
        try:
            stored = self._enc.decrypt_value(client.client_secret)
        except Exception as exc:
            raise InvalidClientError(client_id) from exc
        if not secrets.compare_digest(stored, client_secret):
            raise InvalidClientError(client_id)
        return client

    async def _redirect_uri_allowed(
        self,
        client: OAuthClient,
        redirect_uri: str,
    ) -> bool:
        result = await self._session.execute(
            select(OAuthClientRedirectUri.uri).where(OAuthClientRedirectUri.client_id == client.id)
        )
        patterns = list(result.scalars().all())
        return any(_wildcard_match(p, redirect_uri) for p in patterns)

    async def _enforce_origin(self, client: OAuthClient, origin: str | None) -> None:
        """Reject a cookie flow whose browser origin is not allowed.

        An empty allow-list means "no origin restriction" (the redirect-URI
        allow-list alone governs the flow). A non-empty list requires the
        browser-supplied origin (``Origin`` header, falling back to the
        ``Referer`` host's origin) to match one configured origin exactly.
        """
        result = await self._session.execute(
            select(OAuthClientAllowedOrigin.origin).where(
                OAuthClientAllowedOrigin.client_id == client.id
            )
        )
        allowed = list(result.scalars().all())
        if not allowed:
            return
        if origin is None or not any(secrets.compare_digest(o, origin) for o in allowed):
            raise InvalidOriginError(origin or "<missing>")

    async def _load_refresh_row(self, row_id: uuid.UUID) -> IdpRefreshToken | None:
        return await self._session.get(IdpRefreshToken, row_id)

    # ------------------------------------------------------------------ #
    # Internals — JWE helpers.
    # ------------------------------------------------------------------ #

    def _decrypt(self, token: str) -> dict[str, Any]:
        try:
            payload = self._enc.decrypt_jwe_token(token)
        except Exception as exc:
            raise InvalidGrantError("token decryption failed") from exc
        if not isinstance(payload, dict):
            raise InvalidGrantError("invalid token payload")
        return payload

    def _token_type(self, payload: dict[str, Any]) -> TokenType:
        raw = payload.get(_TYP_CLAIM)
        if not isinstance(raw, str):
            raise InvalidGrantError("missing token type")
        try:
            return TokenType(raw)
        except ValueError as exc:
            raise InvalidGrantError("unknown token type") from exc

    def _verify_pkce(
        self,
        *,
        challenge: str | None,
        method: str | None,
        verifier: str | None,
    ) -> None:
        """Verify the PKCE verifier against the challenge, if a challenge exists."""
        if challenge is None:
            return
        if verifier is None:
            raise InvalidGrantError("missing code_verifier")
        m = method or "plain"
        expected = _derive_code_challenge(verifier, m)
        if not secrets.compare_digest(expected, challenge):
            raise InvalidGrantError("PKCE verification failed")

    def _access_ttl_seconds(self) -> int:
        return self._cfg.auth2_access_token_ttl_seconds


# A distinct token type for the short-lived authorization code. Not part of the
# persistent TokenType enum because it is never stored or used as a bearer
# credential — it is an exchange-only code minted and consumed within minutes.
_AUTH_CODE_TYP = "authorization_code"


# ---------------------------------------------------------------------- #
# Value objects returned to the router.
# ---------------------------------------------------------------------- #


class CallbackContext:
    """The result of ``/auth2/callback``: client redirect + token context.

    ``auth_code`` is ``None`` for the ``cookie`` response type, where the
    session cookie (set by the router) is the sole credential.
    """

    __slots__ = (
        "auth_code",
        "client_id",
        "client_state",
        "expires_in",
        "redirect_uri",
        "response_type",
        "row_id",
        "user_id",
    )

    def __init__(
        self,
        *,
        user_id: uuid.UUID,
        row_id: uuid.UUID,
        client_id: str,
        redirect_uri: str,
        client_state: str | None,
        response_type: str,
        auth_code: str | None,
        expires_in: int,
    ) -> None:
        self.user_id = user_id
        self.row_id = row_id
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_state = client_state
        self.response_type = response_type
        self.auth_code = auth_code
        self.expires_in = expires_in


class TokenPair:
    """An access + refresh token pair with the access-token lifetime."""

    __slots__ = ("access_token", "expires_in", "refresh_token")

    def __init__(self, *, access_token: str, refresh_token: str, expires_in: int) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in


# ---------------------------------------------------------------------- #
# Module-level helpers (pure functions, individually testable).
# ---------------------------------------------------------------------- #


def _claim(claims: dict[str, Any], configured: str | None, default: str) -> str | None:
    """Read a claim by configured name, falling back to the default name."""
    key = configured or default
    value = claims.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _uuid(payload: dict[str, Any], key: str) -> uuid.UUID:
    raw = payload.get(key)
    if not isinstance(raw, str):
        raise InvalidGrantError(f"missing {key}")
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise InvalidGrantError(f"invalid {key}") from exc


def _idp_expiry(idp_tokens: dict[str, Any], drift_seconds: int) -> datetime:
    """Compute the refresh-token row expiry from the IdP response.

    Prefers ``expires_in`` (seconds from now) over an absolute ``expires_at``.
    The drift tolerance is subtracted to avoid treating a token as valid past
    its real expiry due to clock skew.
    """
    expires_in = idp_tokens.get("expires_in")
    if isinstance(expires_in, int | float) and expires_in > 0:
        return _now() + timedelta(seconds=max(0, int(expires_in) - drift_seconds))
    expires_at = idp_tokens.get("expires_at")
    if isinstance(expires_at, int | float) and expires_at > 0:
        return datetime.fromtimestamp(max(0, int(expires_at) - drift_seconds), tz=UTC)
    # No expiry advertised: default to 30 days so the row is usable.
    return _now() + timedelta(days=30)


def _decode_id_token(id_token: str) -> dict[str, Any]:
    """Decode an id_token's payload without verifying its signature.

    The signature is verified by the IdP during the token exchange; here we
    only need the claims to provision the local user. The JWT may be compact
    (three dot-separated base64url segments).
    """
    parts = id_token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload_b64 = parts[1]
        # Add base64url padding.
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        import json

        data = json.loads(decoded)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _generate_code_verifier() -> str:
    """Generate a high-entropy PKCE code verifier (RFC 7636)."""
    return secrets.token_urlsafe(64)


def _derive_code_challenge(verifier: str, method: str) -> str:
    """Derive the PKCE code challenge from a verifier (RFC 7636)."""
    if method.upper() == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    # plain
    return verifier


def _wildcard_match(pattern: str, target: str) -> bool:
    """Match *target* against *pattern*, where ``*`` is a glob wildcard.

    ``*`` matches any run of characters (including ``/``), so
    ``https://*.example.com`` matches ``https://app.example.com`` and
    ``https://app.example.com/*`` matches any path under that prefix. A pattern
    without wildcards must match exactly.
    """
    if "*" not in pattern:
        return secrets.compare_digest(pattern, target)
    # Build a regex: escape everything, then turn escaped \* into .*.
    parts = pattern.split("*")
    escaped = ".*".join(re.escape(p) for p in parts)
    return re.fullmatch(escaped, target) is not None


def _join_url(base: str, path: str, params: dict[str, str] | None = None) -> str:
    """Join a base URL and path, optionally appending query params."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    if params:
        from urllib.parse import urlencode

        url = f"{url}?{urlencode(params)}"
    return url
