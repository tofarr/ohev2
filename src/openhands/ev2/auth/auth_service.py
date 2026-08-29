"""Service layer for the federated OAuth (auth) feature.

The project acts as a federated OAuth proxy:

1. ``/auth/authorize`` validates the client + redirect URI, then redirects the
   browser to the IdP authorization endpoint. A short-lived signed "pending
   auth" JWE is carried as the IdP ``state`` so the callback can recover the
   client context (client id, redirect uri, client state, PKCE challenge).
2. ``/auth/callback`` exchanges the IdP code for IdP tokens, extracts the
   user identity from the id_token (or refresh-token JWT), JIT-provisions or
   looks up the local user, persists the encrypted IdP refresh *and* access
   tokens (synced expiries), and mints a short-lived authorization code (JWE)
   that the client exchanges at ``/auth/token``. A session cookie is also set
   so browser flows work without a second round trip.
3. ``/auth/token`` exchanges the authorization code for our access + refresh
   tokens, validating PKCE and the client secret.
4. ``/auth/refresh`` rotates the access + refresh pair by refreshing the IdP
   refresh token and re-persisting both rows. The refresh is gated by a
   ``SELECT ... FOR UPDATE`` row lock (with a lock timeout) so concurrent
   processes do not refresh the same IdP token simultaneously; a waiter that
   acquires the lock re-checks the row and skips the IdP call if another
   process already refreshed it.
5. ``/auth/revoke`` (RFC 7009) best-effort-revokes a token: deleting the
   ``idp_refresh_tokens`` row (cascading to its access row) for a refresh
   token, or moving the access row's expiry to now for an access token. When
   ``idp.revocation_path`` is configured, the underlying IdP credential is
   also forwarded to the IdP's revocation endpoint (best-effort, failures
   swallowed) before the local row is dropped.

Access tokens are self-contained JWEs (``ttyp: access_token``) so the existing
:func:`get_current_user_id` dependency authenticates them unchanged; their
``exp`` is synced to the backing IdP access-token row's expiry. Refresh tokens
are JWEs (``ttyp: idp_refresh_token``) carrying the ``idp_refresh_tokens`` row
id; only the auth refresh endpoint accepts them. The cookie flow mints a JWE
session cookie (``ttyp: cookie``) carrying the access-token row id + expiry so
the auth dependency can auto-refresh it server-side when it is about to expire
(mirroring what a standard OAuth client does at ``/auth/refresh``).

All IdP HTTP calls go through :class:`httpx.AsyncClient`; tests inject a mock
transport. Sensitive values (IdP refresh token, IdP access token, client
secret) are encrypted at rest via the encryption service (AGENTS.md §9).
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
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import (
    IdpAccessToken,
    IdpRefreshToken,
    OAuthClient,
    OAuthClientRedirectUri,
    TokenType,
)
from openhands.ev2.auth.auth_schemas import (
    OAuthClientBatchCreate,
    OAuthClientBatchDelete,
    OAuthClientBatchOp,
    OAuthClientBatchUpdate,
    OAuthClientCreate,
    OAuthClientUpdate,
)
from openhands.ev2.config import AppConfig, IdpConfig, get_config
from openhands.ev2.encryption.encryption_service import (
    EncryptionService,
    get_encryption_service,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import SearchFilter

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
_ROW_ID_CLAIM = "rid"  # idp_refresh_tokens row id
_ACCESS_ID_CLAIM = "aid"  # idp_access_tokens row id
_ACCESS_EXP_CLAIM = "axp"  # access-token expiry (epoch seconds), for cookie sync
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


class AuthError(Exception):
    """Base class for auth domain errors."""


class InvalidClientError(AuthError):
    """The client_id / client_secret pair is unknown or disabled."""


class InvalidRedirectUriError(AuthError):
    """The redirect_uri is not permitted for the client."""


class InvalidGrantError(AuthError):
    """The authorization code or refresh token is invalid/expired/revoked."""


class IdpError(AuthError):
    """The identity provider returned an error or an unusable response."""


class RefreshLockTimeoutError(AuthError):
    """The refresh-row lock could not be acquired within the timeout.

    A concurrent refresh is in progress; the caller should retry or
    re-authenticate rather than block indefinitely.
    """


class OAuthClientNotFoundError(Exception):
    """Raised when an OAuth client id does not exist or is out of scope."""


class OAuthClientConflictError(Exception):
    """Raised when a create/update collides with an existing client_id."""


class OAuthClientPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


def _now() -> datetime:
    return datetime.now(UTC)


class AuthService:
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
        self._idp = self._cfg.idp

    async def aclose(self) -> None:
        """Close the IdP HTTP client if this service owns it."""
        if self._owns_client:
            await self._http.aclose()

    def _idp_base(self) -> str:
        """Resolve the IdP base URL, making a relative ``idp.url`` absolute.

        ``idp.url`` may be a path-only sentinel (``/auth/dev``) that selects the
        built-in dev identity provider (see ``auth.dev_router``). A relative
        URL works for browser redirects (the browser resolves it against the
        request origin) but not for the server-side ``httpx`` token calls, so it
        is joined against the configured public ``base_url`` here. Absolute
        URLs (``http(s)://…``) are returned unchanged.
        """
        url = self._idp.url
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return f"{self._cfg.base_url.rstrip('/')}/{url.lstrip('/')}"

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
    ) -> str:
        """Validate the client + redirect URI and return the IdP authorize URL.

        *response_type* is the provider-facing value (``code`` or ``cookie``)
        recorded in the pending-auth state so the callback knows whether to
        mint an exchangeable code (``code``) or only set a session cookie
        (``cookie``). The IdP request itself is always a code flow.

        Raises :class:`InvalidClientError` / :class:`InvalidRedirectUriError`.
        """
        if response_type not in _RESPONSE_TYPES:
            raise AuthError(f"response_type must be one of {_RESPONSE_TYPES}")
        client = await self._load_client(client_id)
        if not await self._redirect_uri_allowed(client, redirect_uri):
            raise InvalidRedirectUriError(redirect_uri)

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
            "client_id": self._idp.client_id,
            "redirect_uri": callback_url,
            "state": idp_state,
            "scope": " ".join(self._idp.scopes),
            "code_challenge": idp_challenge,
            "code_challenge_method": "S256",
        }
        return _join_url(self._idp_base(), self._idp.authorize_path, params)

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
        refresh_row, access_row = await self._persist_idp_tokens(user.id, idp_tokens)

        response_type = pending["response_type"]
        auth_code: str | None = None
        if response_type == _RESPONSE_TYPE_CODE:
            auth_code = self._mint_auth_code(
                user_id=user.id,
                row_id=refresh_row.id,
                access_id=access_row.id,
                client_id=pending["client_id"],
                redirect_uri=pending["redirect_uri"],
                client_code_challenge=pending["client_code_challenge"],
                client_code_method=pending["client_code_method"],
            )
        return CallbackContext(
            user_id=user.id,
            row_id=refresh_row.id,
            access_id=access_row.id,
            access_expires_at=access_row.expires_at,
            client_id=pending["client_id"],
            redirect_uri=pending["redirect_uri"],
            client_state=pending["client_state"],
            response_type=response_type,
            auth_code=auth_code,
            expires_in=_seconds_until(access_row.expires_at),
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
        access_id = _uuid(payload, _ACCESS_ID_CLAIM)
        refresh_row, access_row = await self._load_token_rows(row_id, access_id)
        if refresh_row is None or refresh_row.user_id != user_id:
            raise InvalidGrantError("stale authorization code")
        if access_row is None or access_row.refresh_token_id != refresh_row.id:
            raise InvalidGrantError("stale authorization code")
        return await self._mint_token_pair(user_id, refresh_row, access_row)

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

        This is the explicit client-facing refresh grant (``/auth/refresh``):
        the client decided its access token is about to expire and is
        requesting a fresh pair, so the IdP refresh is always performed. The
        IdP refresh is gated by a ``SELECT ... FOR UPDATE`` row lock so
        concurrent processes do not refresh the same IdP token at once; after
        acquiring the lock the row is re-checked, and if another process
        already refreshed it (expiry now in the future) the IdP call is
        skipped and the existing rows are reused. On lock timeout the refresh
        is abandoned with :class:`RefreshLockTimeoutError`.

        Raises :class:`InvalidClientError` / :class:`InvalidGrantError` /
        :class:`IdpError` / :class:`RefreshLockTimeoutError`.
        """
        await self._authenticate_client(client_id, client_secret)
        payload = self._decrypt(refresh_token)
        if self._token_type(payload) is not TokenType.IDP_REFRESH_TOKEN:
            raise InvalidGrantError("not a refresh token")
        row_id = _uuid(payload, _ROW_ID_CLAIM)
        user_id = _uuid(payload, _SUB_CLAIM)
        refresh_row, access_row = await self._lock_token_rows(row_id)
        if refresh_row is None or refresh_row.user_id != user_id:
            raise InvalidGrantError("refresh token not recognized")
        if refresh_row.expires_at <= _now():
            raise InvalidGrantError("refresh token expired")
        if access_row is None:
            raise InvalidGrantError("refresh token not recognized")

        await self._refresh_rows(refresh_row, access_row)
        return await self._mint_token_pair(user_id, refresh_row, access_row)

    # ------------------------------------------------------------------ #
    # /revoke — RFC 7009 token revocation (best-effort).
    # ------------------------------------------------------------------ #

    async def revoke_token(
        self,
        *,
        token: str,
        token_type_hint: str | None,
        client_id: str,
        client_secret: str,
    ) -> None:
        """Revoke a token (RFC 7009).

        Client credentials are always validated (raising
        :class:`InvalidClientError`); the token itself is best-effort — any
        decrypt/parse failure is swallowed and the call returns normally, so the
        endpoint can always answer 200 per §2.2 without leaking token validity.

        Refresh tokens are revoked immediately and irrevocably: the backing
        ``idp_refresh_tokens`` row is deleted, cascading to its
        ``idp_access_tokens`` row, so the federated session can no longer be
        refreshed. Access tokens are best-effort: the backing access row's
        ``expires_at`` is moved to now so the session won't refresh, but the
        already-minted JWE remains usable until its own short ``exp`` elapses
        (Option A — the auth hot path does not check the row).

        When ``idp.revocation_path`` is configured, the underlying IdP
        credential is also forwarded to the IdP's revocation endpoint
        (best-effort) before the local row is dropped, so a compromised IdP
        refresh/access token cannot be replayed directly against the IdP. IdP
        revocation failures are swallowed — the local revocation is
        authoritative for the project's session and must always succeed.
        """
        await self._authenticate_client(client_id, client_secret)
        try:
            payload = self._decrypt(token)
            token_type = self._token_type(payload)
            if token_type is TokenType.IDP_REFRESH_TOKEN:
                row_id = _uuid(payload, _ROW_ID_CLAIM)
                refresh_row = await self._session.get(IdpRefreshToken, row_id)
                if refresh_row is not None:
                    await self._revoke_with_idp(refresh_row.refresh_token)
                    await self._session.execute(
                        delete(IdpRefreshToken).where(IdpRefreshToken.id == row_id)
                    )
            elif token_type is TokenType.ACCESS_TOKEN:
                access_id = _uuid(payload, _ACCESS_ID_CLAIM)
                access_row = await self._session.get(IdpAccessToken, access_id)
                if access_row is not None:
                    await self._revoke_with_idp(access_row.access_token)
                    access_row.expires_at = _now()
            # Other token types (cookie, api_key, legacy refresh_token) are not
            # issued by this provider to clients, so revocation is a no-op.
            await self._session.flush()
        except InvalidGrantError:
            # Unknown/garbage token: best-effort no-op per RFC 7009 §2.2.
            return

    # ------------------------------------------------------------------ #
    # Background cleanup of expired IdP refresh tokens.
    # ------------------------------------------------------------------ #

    async def delete_expired_tokens(self) -> int:
        """Delete expired IdP refresh tokens older than the configured age.

        Rows whose ``expires_at`` is in the past and older than
        ``idp.delete_expired_seconds`` (measured from now) are removed. Returns
        the number of rows deleted.
        """
        cutoff = _now() - timedelta(seconds=self._idp.delete_expired_seconds)
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
    # Cookie flow — mint + auto-refresh the session cookie.
    # ------------------------------------------------------------------ #

    def mint_session_cookie(
        self,
        user_id: uuid.UUID,
        access_row: IdpAccessToken,
    ) -> str:
        """Mint a session-cookie JWE synced to the access token row.

        Carries ``sub`` (user_id), ``aid`` (access-token row id) and ``axp``
        (access-token expiry, epoch seconds) so the auth dependency can detect
        when the cookie is about to expire and trigger a server-side refresh
        (mirroring what a standard OAuth client does at ``/auth/refresh``).
        """
        return _mint_cookie_jwe(
            self._enc,
            user_id=user_id,
            access_id=access_row.id,
            access_expires_at=access_row.expires_at,
        )

    async def refresh_access_token(
        self,
        access_token_id: uuid.UUID,
    ) -> tuple[IdpAccessToken, IdpRefreshToken]:
        """Refresh the IdP access token backing *access_token_id*.

        Used by the cookie auto-refresh path. Acquires a ``FOR UPDATE`` lock on
        the backing refresh row (with a lock timeout), re-checks whether the
        access token still needs refreshing, performs the IdP refresh if so,
        and returns the (possibly updated) access + refresh rows. On lock
        timeout raises :class:`RefreshLockTimeoutError`.
        """
        access_row = await self._session.get(IdpAccessToken, access_token_id)
        if access_row is None:
            raise InvalidGrantError("access token not recognized")
        refresh_row, locked_access = await self._lock_token_rows(access_row.refresh_token_id)
        if refresh_row is None:
            raise InvalidGrantError("access token not recognized")
        # _lock_token_rows returns rows ordered by refresh id; use the locked
        # access row that matches the requested id.
        access_row = locked_access or access_row
        if refresh_row.expires_at <= _now():
            raise InvalidGrantError("refresh token expired")
        await self._refresh_rows_if_needed(refresh_row, access_row)
        return access_row, refresh_row

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
        enabled: bool,
    ) -> OAuthClient:
        """Create an OAuth client with an encrypted secret and redirect URIs.

        Raises :class:`OAuthClientConflictError` if the ``client_id`` is taken.
        """
        client = OAuthClient(
            client_id=client_id,
            client_secret=self._enc.encrypt_value(client_secret),
            name=name,
            enabled=enabled,
        )
        self._session.add(client)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise OAuthClientConflictError(client_id) from exc
        for uri in redirect_uris:
            self._session.add(OAuthClientRedirectUri(client_id=client.id, uri=uri))
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
    # Permission-scoped OAuth client CRUD (used by the REST router + batch).
    # The methods above operate on raw rows for the auth flow (authorize/
    # callback/token); these scope reads/writes to the principal's
    # ``perm_filter`` so the REST surface enforces authorization in the
    # service, not just the router (AGENTS.md §9).
    # ------------------------------------------------------------------ #

    async def create_oauth_client(
        self,
        payload: OAuthClientCreate,
        perm_filter: SearchFilter[OAuthClient],
    ) -> OAuthClient:
        """Create an OAuth client scoped to *perm_filter*.

        Raises :class:`OAuthClientPermissionScopeError` if the prospective
        client does not satisfy *perm_filter*, and :class:`OAuthClientConflictError`
        on a duplicate ``client_id``.
        """
        # Build the row to evaluate the filter before persisting; the secret is
        # encrypted so the in-memory match runs against the stored shape.
        client = OAuthClient(
            client_id=payload.client_id,
            client_secret=self._enc.encrypt_value(payload.client_secret),
            name=payload.name,
            enabled=payload.enabled,
        )
        if not perm_filter.matches(client):
            raise OAuthClientPermissionScopeError(payload.client_id)
        return await self.create_client(
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            name=payload.name,
            redirect_uris=payload.redirect_uris,
            enabled=payload.enabled,
        )

    async def get_oauth_client(
        self,
        client_id: uuid.UUID,
        perm_filter: SearchFilter[OAuthClient],
    ) -> OAuthClient:
        """Retrieve a client by id, scoped by *perm_filter*.

        Raises :class:`OAuthClientNotFoundError` if the client is missing or out
        of scope (so callers return 404 without leaking existence).
        """
        stmt = perm_filter.filter_sql(select(OAuthClient).where(OAuthClient.id == client_id))
        result = await self._session.execute(stmt)
        client = result.scalar_one_or_none()
        if client is None:
            raise OAuthClientNotFoundError(str(client_id))
        return client

    async def get_many_oauth_clients(
        self,
        client_ids: list[uuid.UUID],
        perm_filter: SearchFilter[OAuthClient],
    ) -> list[OAuthClient | None]:
        """Retrieve clients by ids in a single query, scoped by *perm_filter*.

        Returns a list positionally aligned with *client_ids*: the i-th entry is
        the :class:`OAuthClient` for ``client_ids[i]`` or ``None`` when
        missing/out of scope. Duplicate ids are preserved. An empty *client_ids*
        yields an empty list without hitting the DB.
        """
        if not client_ids:
            return []
        stmt = perm_filter.filter_sql(select(OAuthClient).where(OAuthClient.id.in_(client_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, OAuthClient] = {c.id: c for c in result.scalars().all()}
        return [by_id.get(cid) for cid in client_ids]

    async def update_oauth_client(
        self,
        client_id: uuid.UUID,
        payload: OAuthClientUpdate,
        perm_filter: SearchFilter[OAuthClient],
    ) -> OAuthClient:
        """Partially update a client scoped by *perm_filter*.

        Raises :class:`OAuthClientNotFoundError` if missing/out of scope and
        :class:`OAuthClientConflictError` on a duplicate ``client_id``.
        """
        client = await self.get_oauth_client(client_id, perm_filter)
        if payload.name is not None:
            client.name = payload.name
        if payload.client_secret is not None:
            client.client_secret = self._enc.encrypt_value(payload.client_secret)
        if payload.redirect_uris is not None:
            await self.replace_redirect_uris(client, payload.redirect_uris)
        if payload.enabled is not None:
            client.enabled = payload.enabled
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise OAuthClientConflictError(str(client_id)) from exc
        await self._session.refresh(client)
        return client

    async def delete_oauth_client(
        self,
        client_id: uuid.UUID,
        perm_filter: SearchFilter[OAuthClient],
    ) -> None:
        """Delete a client scoped by *perm_filter*. Raises if missing/out of scope."""
        client = await self.get_oauth_client(client_id, perm_filter)
        await self.delete_client(client)

    async def apply_client_batch(
        self,
        operations: list[OAuthClientBatchOp],
        perm_filters: dict[Action, SearchFilter[OAuthClient] | None],
    ) -> list[OAuthClient | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic: a failure of
        any operation rolls back the entire batch). Returns results aligned with
        *operations*: the client for create/update, ``None`` for delete.
        """
        results: list[OAuthClient | None] = []
        for op in operations:
            if isinstance(op, OAuthClientBatchCreate):
                results.append(await self._batch_create_client(op, perm_filters))
            elif isinstance(op, OAuthClientBatchUpdate):
                results.append(await self._batch_update_client(op, perm_filters))
            elif isinstance(op, OAuthClientBatchDelete):
                await self._batch_delete_client(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create_client(
        self,
        op: OAuthClientBatchCreate,
        perm_filters: dict[Action, SearchFilter[OAuthClient] | None],
    ) -> OAuthClient:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await self.create_oauth_client(op.data, filt)

    async def _batch_update_client(
        self,
        op: OAuthClientBatchUpdate,
        perm_filters: dict[Action, SearchFilter[OAuthClient] | None],
    ) -> OAuthClient:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await self.update_oauth_client(op.id, op.data, filt)

    async def _batch_delete_client(
        self,
        op: OAuthClientBatchDelete,
        perm_filters: dict[Action, SearchFilter[OAuthClient] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await self.delete_oauth_client(op.id, filt)

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
            "client_id": self._idp.client_id,
            "client_secret": self._idp.client_secret.get_secret_value(),
            "code_verifier": verifier,
        }
        return await self._idp_token_post(data)

    async def _refresh_with_idp(self, refresh_token: str) -> dict[str, Any]:
        """Refresh the IdP access token using a refresh token (RFC 6749 §6)."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._idp.client_id,
            "client_secret": self._idp.client_secret.get_secret_value(),
        }
        return await self._idp_token_post(data)

    async def _idp_token_post(self, data: dict[str, str]) -> dict[str, Any]:
        url = _join_url(self._idp_base(), self._idp.token_path)
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

    async def _revoke_with_idp(self, encrypted_credential: str) -> None:
        """Forward a revocation to the IdP (RFC 7009, best-effort).

        *encrypted_credential* is the at-rest-encrypted IdP refresh or access
        token from the backing row; it is decrypted here and POSTed to the IdP's
        revocation endpoint. When ``idp.revocation_path`` is unset (the default)
        this is a no-op — the local revocation is authoritative on its own.

        Any failure (network error, non-2xx response) is swallowed: the caller's
        local revocation must still succeed so the project's own session is
        killed regardless of IdP availability. The IdP call is only a
        defense-in-depth measure against direct replay of a compromised IdP
        credential.
        """
        path = self._idp.revocation_path
        if path is None:
            return
        credential = self._enc.decrypt_value(encrypted_credential)
        url = _join_url(self._idp_base(), path)
        data = {
            "token": credential,
            "client_id": self._idp.client_id,
            "client_secret": self._idp.client_secret.get_secret_value(),
        }
        try:
            resp = await self._http.post(url, data=data)
        except httpx.HTTPError:
            return
        # RFC 7009 §2.2: the IdP returns 200 for valid, invalid, and already-
        # revoked tokens alike. Any non-2xx is treated as best-effort failure.
        if not resp.is_success:
            return

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
        idp_user_id = _claim(claims, self._idp.user_id_field, "sub")
        email = _claim(claims, self._idp.email_field, "email")

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

    async def _persist_idp_tokens(
        self,
        user_id: uuid.UUID,
        idp_tokens: dict[str, Any],
    ) -> tuple[IdpRefreshToken, IdpAccessToken]:
        """Encrypt and persist the IdP refresh + access tokens for *user_id*.

        Both expiries are drift-adjusted and sourced from the IdP response
        (with config fallbacks). Returns (refresh_row, access_row).
        """
        refresh = idp_tokens.get("refresh_token")
        if not refresh:
            raise IdpError("IdP token response missing refresh_token")
        access = idp_tokens.get("access_token")
        if not access:
            raise IdpError("IdP token response missing access_token")
        drift = self._idp.expire_drift_tolerance
        refresh_row = IdpRefreshToken(
            user_id=user_id,
            refresh_token=self._enc.encrypt_value(refresh),
            expires_at=_idp_refresh_expiry(idp_tokens, drift, self._idp),
        )
        self._session.add(refresh_row)
        await self._session.flush()
        access_row = IdpAccessToken(
            refresh_token_id=refresh_row.id,
            access_token=self._enc.encrypt_value(access),
            expires_at=_idp_access_expiry(idp_tokens, drift, self._idp),
        )
        self._session.add(access_row)
        await self._session.flush()
        await self._session.refresh(access_row)
        return refresh_row, access_row

    async def persist_idp_tokens(
        self,
        user_id: uuid.UUID,
        idp_tokens: dict[str, Any],
    ) -> tuple[IdpRefreshToken, IdpAccessToken]:
        """Public entry point for :meth:`_persist_idp_tokens`.

        Exposed so the dev login endpoint can persist a freshly issued IdP
        token pair (from the dev IdP) through the same path the OAuth callback
        uses, without re-implementing encryption-at-rest or expiry syncing.
        """
        return await self._persist_idp_tokens(user_id, idp_tokens)

    async def _load_token_rows(
        self,
        refresh_id: uuid.UUID,
        access_id: uuid.UUID,
    ) -> tuple[IdpRefreshToken | None, IdpAccessToken | None]:
        """Load the refresh + access rows by id (no lock)."""
        refresh_row = await self._session.get(IdpRefreshToken, refresh_id)
        access_row = await self._session.get(IdpAccessToken, access_id)
        return refresh_row, access_row

    async def _lock_token_rows(
        self,
        refresh_id: uuid.UUID,
    ) -> tuple[IdpRefreshToken | None, IdpAccessToken | None]:
        """Lock the refresh row ``FOR UPDATE`` and load its access row.

        A per-transaction ``SET LOCAL lock_timeout`` bounds the wait so a
        concurrent holder causes the waiter to abandon the refresh with
        :class:`RefreshLockTimeoutError` instead of blocking forever. After
        acquiring the lock the caller must re-check the row's expiry — a
        concurrent process may have refreshed it already. Returns
        ``(refresh_row, access_row)``; either may be ``None`` if missing.
        """
        timeout_ms = int(self._idp.refresh_lock_timeout_seconds * 1000)
        await self._session.execute(text(f"SET LOCAL lock_timeout = {timeout_ms}"))
        try:
            result = await self._session.execute(
                select(IdpRefreshToken).where(IdpRefreshToken.id == refresh_id).with_for_update(),
            )
        except OperationalError as exc:
            raise RefreshLockTimeoutError("could not acquire refresh lock within timeout") from exc
        refresh_row = result.scalar_one_or_none()
        if refresh_row is None:
            return None, None
        access_result = await self._session.execute(
            select(IdpAccessToken).where(IdpAccessToken.refresh_token_id == refresh_row.id)
        )
        access_row = access_result.scalar_one_or_none()
        return refresh_row, access_row

    async def _refresh_rows_if_needed(
        self,
        refresh_row: IdpRefreshToken,
        access_row: IdpAccessToken,
    ) -> None:
        """Refresh the IdP tokens if the access token has expired.

        Used by the cookie auto-refresh path: re-check after acquiring the
        lock — if the access row's expiry is still in the future another
        process already refreshed it, so the IdP call is skipped and the
        existing rows are reused. Otherwise perform the IdP refresh.
        """
        if access_row.expires_at > _now():
            return
        await self._refresh_rows(refresh_row, access_row)

    async def _refresh_rows(
        self,
        refresh_row: IdpRefreshToken,
        access_row: IdpAccessToken,
    ) -> None:
        """Perform the IdP refresh and rewrite both rows in place.

        Used by the explicit ``/auth/refresh`` grant: the client requested a
        rotation, so the IdP refresh-token grant is always performed. The
        row lock held by the caller serializes concurrent refreshes of the
        same IdP token so the IdP is not asked twice in parallel.
        """
        idp_refresh = self._enc.decrypt_value(refresh_row.refresh_token)
        idp_tokens = await self._refresh_with_idp(idp_refresh)
        new_idp_refresh = idp_tokens.get("refresh_token") or idp_refresh
        new_idp_access = idp_tokens.get("access_token")
        if not new_idp_access:
            raise IdpError("IdP refresh response missing access_token")
        drift = self._idp.expire_drift_tolerance
        refresh_row.refresh_token = self._enc.encrypt_value(new_idp_refresh)
        refresh_row.expires_at = _idp_refresh_expiry(idp_tokens, drift, self._idp)
        access_row.access_token = self._enc.encrypt_value(new_idp_access)
        access_row.expires_at = _idp_access_expiry(idp_tokens, drift, self._idp)
        await self._session.flush()

    # ------------------------------------------------------------------ #
    # Internals — token minting.
    # ------------------------------------------------------------------ #

    async def _mint_token_pair(
        self,
        user_id: uuid.UUID,
        refresh_row: IdpRefreshToken,
        access_row: IdpAccessToken,
    ) -> TokenPair:
        """Mint an access token + refresh token pair synced to the IdP rows.

        The access-token JWE ``exp`` is synced to the access row's expiry; the
        refresh-token JWE ``exp`` is synced to the refresh row's expiry.
        """
        access = self._mint_access_token(user_id, access_row)
        refresh = self._mint_refresh_token(user_id, refresh_row)
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=_seconds_until(access_row.expires_at),
            refresh_expires_at=refresh_row.expires_at,
            access_expires_at=access_row.expires_at,
        )

    def _mint_access_token(self, user_id: uuid.UUID, access_row: IdpAccessToken) -> str:
        """Mint a self-contained access token (``ttyp: access_token``).

        Its ``exp`` is synced to the backing IdP access-token row's expiry so a
        client token never outlives the federated credential backing it.
        """
        ttl = access_row.expires_at - _now()
        if ttl.total_seconds() <= 0:
            ttl = timedelta(seconds=1)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.ACCESS_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ACCESS_ID_CLAIM: str(access_row.id),
            },
            expires_in=ttl,
        )

    def _mint_refresh_token(
        self,
        user_id: uuid.UUID,
        refresh_row: IdpRefreshToken,
    ) -> str:
        """Mint a refresh token (``ttyp: idp_refresh_token``) carrying the row id.

        Its ``exp`` is synced to the IdP refresh-token row's expiry so the JWE
        itself reflects the federated refresh-token lifetime.
        """
        ttl = refresh_row.expires_at - _now()
        if ttl.total_seconds() <= 0:
            ttl = timedelta(seconds=1)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.IDP_REFRESH_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ROW_ID_CLAIM: str(refresh_row.id),
            },
            expires_in=ttl,
        )

    def _mint_auth_code(
        self,
        *,
        user_id: uuid.UUID,
        row_id: uuid.UUID,
        access_id: uuid.UUID,
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
            _ACCESS_ID_CLAIM: str(access_id),
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


# A distinct token type for the short-lived authorization code. Not part of the
# persistent TokenType enum because it is never stored or used as a bearer
# credential — it is an exchange-only code minted and consumed within minutes.
_AUTH_CODE_TYP = "authorization_code"


# ---------------------------------------------------------------------- #
# Value objects returned to the router.
# ---------------------------------------------------------------------- #


class CallbackContext:
    """The result of ``/auth/callback``: client redirect + token context.

    ``auth_code`` is ``None`` for the ``cookie`` response type, where the
    session cookie (set by the router) is the sole credential. ``access_id``
    and ``access_expires_at`` back the cookie the router mints for the cookie
    flow; ``row_id`` is the refresh-token row id carried in the auth code.
    """

    __slots__ = (
        "access_expires_at",
        "access_id",
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
        access_id: uuid.UUID,
        access_expires_at: datetime,
        client_id: str,
        redirect_uri: str,
        client_state: str | None,
        response_type: str,
        auth_code: str | None,
        expires_in: int,
    ) -> None:
        self.user_id = user_id
        self.row_id = row_id
        self.access_id = access_id
        self.access_expires_at = access_expires_at
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_state = client_state
        self.response_type = response_type
        self.auth_code = auth_code
        self.expires_in = expires_in


class TokenPair:
    """An access + refresh token pair with synced federated expiries."""

    __slots__ = (
        "access_expires_at",
        "access_token",
        "expires_in",
        "refresh_expires_at",
        "refresh_token",
    )

    def __init__(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_in: int,
        refresh_expires_at: datetime,
        access_expires_at: datetime,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.refresh_expires_at = refresh_expires_at
        self.access_expires_at = access_expires_at


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


def _idp_access_expiry(
    idp_tokens: dict[str, Any],
    drift_seconds: int,
    idp: IdpConfig,
) -> datetime:
    """Compute the IdP *access*-token row expiry from the IdP response.

    Prefers ``expires_in`` (seconds from now) over an absolute ``expires_at``;
    when the IdP advertises neither, ``idp.access_token_expires_in`` is the
    fallback. The drift tolerance is subtracted to avoid treating a token as
    valid past its real expiry due to clock skew.
    """
    expires_in = idp_tokens.get("expires_in")
    if isinstance(expires_in, int | float) and expires_in > 0:
        return _now() + timedelta(seconds=max(0, int(expires_in) - drift_seconds))
    expires_at = idp_tokens.get("expires_at")
    if isinstance(expires_at, int | float) and expires_at > 0:
        return datetime.fromtimestamp(max(0, int(expires_at) - drift_seconds), tz=UTC)
    return _now() + timedelta(seconds=max(1, idp.access_token_expires_in - drift_seconds))


def _idp_refresh_expiry(
    idp_tokens: dict[str, Any],
    drift_seconds: int,
    idp: IdpConfig,
) -> datetime:
    """Compute the IdP *refresh*-token row expiry from the IdP response.

    Prefers ``refresh_expires_in`` (seconds from now) over an absolute
    ``refresh_expires_at``; when the IdP advertises neither,
    ``idp.refresh_token_expires_in`` is the fallback. The drift tolerance is
    subtracted to avoid treating a token as valid past its real expiry.
    """
    refresh_expires_in = idp_tokens.get("refresh_expires_in")
    if isinstance(refresh_expires_in, int | float) and refresh_expires_in > 0:
        return _now() + timedelta(seconds=max(0, int(refresh_expires_in) - drift_seconds))
    refresh_expires_at = idp_tokens.get("refresh_expires_at")
    if isinstance(refresh_expires_at, int | float) and refresh_expires_at > 0:
        return datetime.fromtimestamp(max(0, int(refresh_expires_at) - drift_seconds), tz=UTC)
    return _now() + timedelta(seconds=max(1, idp.refresh_token_expires_in - drift_seconds))


def _seconds_until(expires_at: datetime) -> int:
    """Seconds from now until *expires_at*, floored at 0."""
    delta = (expires_at - _now()).total_seconds()
    return max(0, int(delta))


def _mint_cookie_jwe(
    enc: EncryptionService,
    *,
    user_id: uuid.UUID,
    access_id: uuid.UUID,
    access_expires_at: datetime,
) -> str:
    """Mint a session-cookie JWE synced to an IdP access-token row.

    Carries ``sub`` (user_id), ``aid`` (access-token row id) and ``axp``
    (access-token expiry, epoch seconds) so the auth dependency can detect
    when the cookie is about to expire and trigger a server-side refresh.
    """
    ttl = access_expires_at - _now()
    if ttl.total_seconds() <= 0:
        ttl = timedelta(seconds=1)
    return enc.create_jwe_token(
        {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: TokenType.COOKIE.value,
            _JTI_CLAIM: str(uuid.uuid4()),
            _ACCESS_ID_CLAIM: str(access_id),
            _ACCESS_EXP_CLAIM: int(access_expires_at.timestamp()),
        },
        expires_in=ttl,
    )


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
