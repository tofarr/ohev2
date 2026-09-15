"""Service layer for the :class:`OAuthSession` resource + login/consent flow.

Handles:

* **Login/consent flow** — mirrors the existing IdP flow (§9) but scoped by
  provider: authorize builds the provider authorize URL (PKCE S256 + signed
  state); callback exchanges the code and persists the session.
* **Lazy refresh** — refresh-on-read-when-expired, using the provider's
  ``expire_drift_tolerance``. Concurrency mirrors the IdP pattern (§9):
  ``SELECT ... FOR UPDATE`` + ``SET LOCAL lock_timeout``; re-check after lock.
* **CRUD** — standard read/update/delete + batch (create is via the flow).

Token encryption at rest (§13): ``access_token`` and ``refresh_token`` are JWE
ciphertext. The tokens are never exposed through this surface — only through
``/secret-values`` (sub-issue #145).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.oauth.oauth_provider_models import OAuthProvider
from openhands.ev2.oauth.oauth_session_models import OAuthSession
from openhands.ev2.oauth.oauth_session_schemas import (
    OAuthSessionBatchDelete,
    OAuthSessionBatchOp,
    OAuthSessionBatchUpdate,
    OAuthSessionRead,
    OAuthSessionSearchFilter,
    OAuthSessionUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

_PENDING_AUTH_TTL = timedelta(minutes=10)

_STATE_USER_ID_CLAIM = "sub"
_STATE_PROVIDER_ID_CLAIM = "pid"
_STATE_REDIRECT_URI_CLAIM = "ruri"
_STATE_CLIENT_STATE_CLAIM = "cst"
_STATE_VERIFIER_CLAIM = "ivf"
_STATE_SCOPES_CLAIM = "scp"
_STATE_CHALLENGE_CLAIM = "cc"
_STATE_CHALLENGE_METHOD_CLAIM = "cm"


class OAuthSessionNotFoundError(Exception):
    """Raised when a session does not exist or is out of scope."""


class OAuthSessionUnrecoverableError(Exception):
    """Raised when a session's refresh token is expired/revoked and tolerate_invalid is false."""

    def __init__(self, session_id: uuid.UUID) -> None:
        self.session_id = session_id
        super().__init__(f"OAuth session {session_id} is unrecoverable (refresh token expired)")


class OAuthProviderDisabledError(Exception):
    """Raised when the referenced OAuth provider is not enabled."""


class OAuthProviderError(Exception):
    """Raised when the external OAuth provider returns an error."""


class RefreshLockTimeoutError(Exception):
    """Raised when the refresh row lock cannot be acquired within the timeout."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


def _now() -> datetime:
    return datetime.now(UTC)


def _generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def _derive_code_challenge(verifier: str, method: str) -> str:
    if method.upper() == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier


def _join_url(base: str, path: str, params: dict[str, str] | None = None) -> str:
    url = base.rstrip("/") + "/" + path.lstrip("/")
    if params:
        from urllib.parse import urlencode

        url = f"{url}?{urlencode(params)}"
    return url


def _access_expiry(
    token_response: dict[str, Any],
    drift_seconds: int,
    fallback_expires_in: int,
) -> datetime:
    expires_in = token_response.get("expires_in")
    if isinstance(expires_in, int | float) and expires_in > 0:
        return _now() + timedelta(seconds=max(0, int(expires_in) - drift_seconds))
    expires_at = token_response.get("expires_at")
    if isinstance(expires_at, int | float) and expires_at > 0:
        return datetime.fromtimestamp(max(0, int(expires_at) - drift_seconds), tz=UTC)
    return _now() + timedelta(seconds=max(1, fallback_expires_in - drift_seconds))


def _refresh_expiry(
    token_response: dict[str, Any],
    drift_seconds: int,
    fallback_expires_in: int,
) -> datetime | None:
    refresh_expires_in = token_response.get("refresh_expires_in")
    if isinstance(refresh_expires_in, int | float) and refresh_expires_in > 0:
        return _now() + timedelta(seconds=max(0, int(refresh_expires_in) - drift_seconds))
    refresh_expires_at = token_response.get("refresh_expires_at")
    if isinstance(refresh_expires_at, int | float) and refresh_expires_at > 0:
        return datetime.fromtimestamp(max(0, int(refresh_expires_at) - drift_seconds), tz=UTC)
    return None


class OAuthSessionService:
    """CRUD + login/consent flow + lazy refresh over :class:`OAuthSession` rows."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[OAuthSession] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
        http_client: httpx.AsyncClient | None = None,
        config: AppConfig | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._owns_client = http_client is None
        self._enc = encryption_service or get_encryption_service()
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._cfg = config or get_config()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    def to_read(self, oauth_session: OAuthSession) -> OAuthSessionRead:
        return OAuthSessionRead(
            id=oauth_session.id,
            oauth_provider_id=oauth_session.oauth_provider_id,
            creator_id=oauth_session.creator_id,
            access_token_expires_at=oauth_session.access_token_expires_at,
            refresh_token_expires_at=oauth_session.refresh_token_expires_at,
            tolerate_invalid=oauth_session.tolerate_invalid,
            enabled=oauth_session.enabled,
            created_at=oauth_session.created_at,
            updated_at=oauth_session.updated_at,
        )

    async def build_authorize_url(
        self,
        provider: OAuthProvider,
        *,
        user_id: uuid.UUID,
        redirect_uri: str,
        client_state: str | None,
        scope: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        callback_url: str,
    ) -> str:
        if not provider.enabled:
            raise OAuthProviderDisabledError(str(provider.id))
        verifier = _generate_code_verifier()
        idp_challenge = _derive_code_challenge(verifier, "S256")
        scopes = scope.split() if scope else list(provider.scopes)
        state = self._mint_pending_auth(
            user_id=user_id,
            provider_id=provider.id,
            redirect_uri=redirect_uri,
            client_state=client_state,
            scopes=frozenset(scopes),
            idp_verifier=verifier,
            client_code_challenge=code_challenge,
            client_code_method=code_challenge_method,
        )
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": callback_url,
            "state": state,
            "scope": " ".join(scopes) if scopes else "",
            "code_challenge": idp_challenge,
            "code_challenge_method": "S256",
        }
        return _join_url(provider.url, provider.authorize_path, params)

    async def handle_callback(
        self,
        provider: OAuthProvider,
        *,
        code: str,
        state: str,
        callback_url: str,
    ) -> OAuthSession:
        pending = self._decode_pending_auth(state)
        if pending[_STATE_PROVIDER_ID_CLAIM] != str(provider.id):
            raise OAuthProviderError("state does not match provider")
        token_response = await self._exchange_code(
            provider=provider,
            code=code,
            verifier=pending[_STATE_VERIFIER_CLAIM],
            callback_url=callback_url,
        )
        access = token_response.get("access_token")
        if not access:
            raise OAuthProviderError("provider token response missing access_token")
        refresh = token_response.get("refresh_token")
        if not refresh:
            raise OAuthProviderError("provider token response missing refresh_token")
        drift = provider.expire_drift_tolerance
        oauth_session = OAuthSession(
            oauth_provider_id=provider.id,
            creator_id=uuid.UUID(pending[_STATE_USER_ID_CLAIM]),
            access_token=self._enc.encrypt_value(access),
            refresh_token=self._enc.encrypt_value(refresh),
            access_token_expires_at=_access_expiry(
                token_response, drift, provider.access_token_expires_in
            ),
            refresh_token_expires_at=_refresh_expiry(
                token_response, drift, provider.refresh_token_expires_in
            ),
        )
        self._session.add(oauth_session)
        await self._session.flush()
        await self._session.refresh(oauth_session)
        return oauth_session

    async def _exchange_code(
        self,
        provider: OAuthProvider,
        *,
        code: str,
        verifier: str,
        callback_url: str,
    ) -> dict[str, Any]:
        client_secret = self._enc.decrypt_value(provider.client_secret)
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": provider.client_id,
            "client_secret": client_secret,
            "code_verifier": verifier,
        }
        return await self._provider_token_post(provider, data)

    async def _refresh_with_provider(
        self,
        provider: OAuthProvider,
        refresh_token: str,
    ) -> dict[str, Any]:
        client_secret = self._enc.decrypt_value(provider.client_secret)
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": provider.client_id,
            "client_secret": client_secret,
        }
        return await self._provider_token_post(provider, data)

    async def _provider_token_post(
        self,
        provider: OAuthProvider,
        data: dict[str, str],
    ) -> dict[str, Any]:
        url = _join_url(provider.url, provider.token_path)
        try:
            resp = await self._http.post(url, data=data)
        except httpx.HTTPError as exc:
            raise OAuthProviderError(f"provider token endpoint unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise OAuthProviderError(f"provider token endpoint returned {resp.status_code}")
        body = cast("dict[str, Any]", resp.json())
        if "access_token" not in body:
            raise OAuthProviderError("provider token response missing access_token")
        return body

    async def get_valid_access_token(
        self,
        oauth_session: OAuthSession,
        provider: OAuthProvider,
    ) -> str | None:
        """Return a currently-valid access token, lazily refreshing if needed.

        Returns ``None`` when the session is unrecoverable and
        ``tolerate_invalid`` is ``true``. Raises
        :class:`OAuthSessionUnrecoverableError` when unrecoverable and
        ``tolerate_invalid`` is ``false``.
        """
        if not oauth_session.enabled:
            return None
        drift = timedelta(seconds=provider.expire_drift_tolerance)
        now = _now()
        if oauth_session.access_token_expires_at > now + drift:
            return self._enc.decrypt_value(oauth_session.access_token)
        return await self._refresh_if_needed(oauth_session, provider)

    async def _refresh_if_needed(
        self,
        oauth_session: OAuthSession,
        provider: OAuthProvider,
    ) -> str | None:
        locked = await self._lock_for_refresh(oauth_session)
        if locked is None:
            return None
        drift = timedelta(seconds=provider.expire_drift_tolerance)
        if locked.access_token_expires_at > _now() + drift:
            return self._enc.decrypt_value(locked.access_token)
        if self._is_refresh_expired(locked):
            return None
        await self._do_refresh(locked, provider)
        return self._enc.decrypt_value(locked.access_token)

    async def _lock_for_refresh(self, oauth_session: OAuthSession) -> OAuthSession | None:
        """Acquire a FOR UPDATE lock on the session row."""
        lock_timeout = self._cfg.oauth_session_refresh_lock_timeout_seconds
        timeout_ms = int(lock_timeout * 1000)
        await self._session.execute(text(f"SET LOCAL lock_timeout = {timeout_ms}"))
        try:
            result = await self._session.execute(
                select(OAuthSession).where(OAuthSession.id == oauth_session.id).with_for_update()
            )
        except OperationalError as exc:
            raise RefreshLockTimeoutError(
                "could not acquire session refresh lock within timeout"
            ) from exc
        return result.scalar_one_or_none()

    def _is_refresh_expired(self, locked: OAuthSession) -> bool:
        """Check if the refresh token has expired; raise if unrecoverable."""
        if locked.refresh_token_expires_at is None:
            return False
        if locked.refresh_token_expires_at > _now():
            return False
        if not locked.tolerate_invalid:
            raise OAuthSessionUnrecoverableError(locked.id)
        return True

    async def _do_refresh(
        self,
        oauth_session: OAuthSession,
        provider: OAuthProvider,
    ) -> None:
        refresh_plain = self._enc.decrypt_value(oauth_session.refresh_token)
        token_response = await self._refresh_with_provider(provider, refresh_plain)
        new_access = token_response.get("access_token")
        if not new_access:
            raise OAuthProviderError("provider refresh response missing access_token")
        new_refresh = token_response.get("refresh_token") or refresh_plain
        drift = provider.expire_drift_tolerance
        oauth_session.access_token = self._enc.encrypt_value(new_access)
        oauth_session.access_token_expires_at = _access_expiry(
            token_response, drift, provider.access_token_expires_in
        )
        oauth_session.refresh_token = self._enc.encrypt_value(new_refresh)
        new_refresh_expiry = _refresh_expiry(
            token_response, drift, provider.refresh_token_expires_in
        )
        if new_refresh_expiry is not None:
            oauth_session.refresh_token_expires_at = new_refresh_expiry
        await self._session.flush()

    async def explicit_refresh(
        self,
        oauth_session: OAuthSession,
        provider: OAuthProvider,
    ) -> OAuthSession:
        lock_timeout = self._cfg.oauth_session_refresh_lock_timeout_seconds
        timeout_ms = int(lock_timeout * 1000)
        await self._session.execute(text(f"SET LOCAL lock_timeout = {timeout_ms}"))
        try:
            result = await self._session.execute(
                select(OAuthSession).where(OAuthSession.id == oauth_session.id).with_for_update()
            )
        except OperationalError as exc:
            raise RefreshLockTimeoutError(
                "could not acquire session refresh lock within timeout"
            ) from exc
        locked = result.scalar_one_or_none()
        if locked is None:
            raise OAuthSessionNotFoundError(str(oauth_session.id))
        if (
            locked.refresh_token_expires_at is not None
            and locked.refresh_token_expires_at <= _now()
        ):
            raise OAuthSessionUnrecoverableError(locked.id)
        await self._do_refresh(locked, provider)
        await self._session.refresh(locked)
        return locked

    async def get(self, session_id: uuid.UUID) -> OAuthSession:
        stmt = self._perm_filter.filter_sql(
            select(OAuthSession).where(OAuthSession.id == session_id)
        )
        result = await self._session.execute(stmt)
        oauth_session = result.scalar_one_or_none()
        if oauth_session is None:
            raise OAuthSessionNotFoundError(str(session_id))
        return oauth_session

    async def get_many(self, session_ids: list[uuid.UUID]) -> list[OAuthSession | None]:
        if not session_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(OAuthSession).where(OAuthSession.id.in_(session_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, OAuthSession] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(sid) for sid in session_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: OAuthSessionSearchFilter | None = None,
    ) -> tuple[list[OAuthSession], uuid.UUID | None]:
        stmt = self._perm_filter.filter_sql(select(OAuthSession).order_by(OAuthSession.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(OAuthSession.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: OAuthSessionSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(OAuthSession))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        session_id: uuid.UUID,
        payload: OAuthSessionUpdate,
    ) -> OAuthSession:
        oauth_session = await self.get(session_id)
        if payload.tolerate_invalid is not None:
            oauth_session.tolerate_invalid = payload.tolerate_invalid
        if payload.enabled is not None:
            oauth_session.enabled = payload.enabled
        await self._session.flush()
        await self._session.refresh(oauth_session)
        return oauth_session

    async def delete(self, session_id: uuid.UUID) -> None:
        oauth_session = await self.get(session_id)
        await self._session.execute(delete(OAuthSession).where(OAuthSession.id == oauth_session.id))
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[OAuthSessionBatchOp],
        perm_filters: dict[Action, SearchFilter[OAuthSession] | None],
    ) -> list[OAuthSession | None]:
        results: list[OAuthSession | None] = []
        for op in operations:
            if isinstance(op, OAuthSessionBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, OAuthSessionBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_update(
        self,
        op: OAuthSessionBatchUpdate,
        perm_filters: dict[Action, SearchFilter[OAuthSession] | None],
    ) -> OAuthSession:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await OAuthSessionService(
            self._session, filt, encryption_service=self._enc, http_client=self._http
        ).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: OAuthSessionBatchDelete,
        perm_filters: dict[Action, SearchFilter[OAuthSession] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await OAuthSessionService(
            self._session, filt, encryption_service=self._enc, http_client=self._http
        ).delete(op.id)

    def _mint_pending_auth(
        self,
        *,
        user_id: uuid.UUID,
        provider_id: uuid.UUID,
        redirect_uri: str,
        client_state: str | None,
        scopes: frozenset[str],
        idp_verifier: str,
        client_code_challenge: str | None,
        client_code_method: str | None,
    ) -> str:
        payload: dict[str, Any] = {
            _STATE_USER_ID_CLAIM: str(user_id),
            _STATE_PROVIDER_ID_CLAIM: str(provider_id),
            _STATE_REDIRECT_URI_CLAIM: redirect_uri,
            _STATE_VERIFIER_CLAIM: idp_verifier,
        }
        if client_state is not None:
            payload[_STATE_CLIENT_STATE_CLAIM] = client_state
        if scopes:
            payload[_STATE_SCOPES_CLAIM] = " ".join(sorted(scopes))
        if client_code_challenge is not None:
            payload[_STATE_CHALLENGE_CLAIM] = client_code_challenge
            payload[_STATE_CHALLENGE_METHOD_CLAIM] = client_code_method or "plain"
        return self._enc.create_jwe_token(payload, expires_in=_PENDING_AUTH_TTL)

    def decode_pending_auth(self, state: str) -> dict[str, Any]:
        """Decode and validate a signed state token from the authorize flow."""
        return self._decode_pending_auth(state)

    def _decode_pending_auth(self, state: str) -> dict[str, Any]:
        try:
            payload = self._enc.decrypt_jwe_token(state)
        except Exception as exc:
            raise OAuthProviderError("invalid state") from exc
        if not isinstance(payload, dict):
            raise OAuthProviderError("invalid state")
        if payload.get(_STATE_VERIFIER_CLAIM) is None:
            raise OAuthProviderError("invalid state")
        if payload.get(_STATE_USER_ID_CLAIM) is None:
            raise OAuthProviderError("invalid state")
        if payload.get(_STATE_PROVIDER_ID_CLAIM) is None:
            raise OAuthProviderError("invalid state")
        return payload
