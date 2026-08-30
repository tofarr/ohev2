"""Token issuance, validation, and rotation for the auth feature.

:meth:`TokenService.authenticate` is the single entry point that converts a
JWE-encoded token string into an :class:`AuthToken`. Per-type validity:

* COOKIE / ACCESS_TOKEN — derived from the JWE claims alone; ``enabled`` is
  the user row's ``enabled`` flag (a disabled user cannot use any token).
* API_KEY — resolved by :meth:`TokenService.authenticate_api_key` from an
  opaque plaintext presented via the ``X-API-Key`` header; the row is looked
  up by ``sha256(key)`` and must be live (enabled, not expired), and the user
  must be enabled.
* IDP_REFRESH_TOKEN — the token's ``rid`` must match a live
  ``idp_refresh_tokens`` row, and the user must be enabled. (Refresh tokens
  are not accepted by ``authenticate`` for general requests; they are
  exchanged at the auth refresh endpoint, which is the canonical rotation
  path.)

Every minted token's ``exp`` is synced to the backing IdP row's expiry so a
client credential never outlives the federated grant backing it — the app
server never grants access beyond what the IdP sanctions. The minting
primitives mirror :class:`AuthService`'s (``_mint_access_token`` /
``_mint_refresh_token`` / ``_mint_cookie_jwe``) so both services produce
byte-for-byte interchangeable tokens. Token rotation is performed by
:class:`AuthService.exchange_refresh_token` (the IdP refresh grant); this
service only mints and validates.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import (
    ApiKey,
    AuthToken,
    IdpAccessToken,
    IdpRefreshToken,
    TokenType,
)
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.user.user_models import User

_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"
_JTI_CLAIM = "jti"
_IAT_CLAIM = "iat"
_EXP_CLAIM = "exp"
_SCOPE_CLAIM = "scp"
# Federated-cookie / access-token claims mirroring AuthService so tokens minted
# here are indistinguishable from those minted by the OAuth callback.
_ACCESS_ID_CLAIM = "aid"  # idp_access_tokens row id
_ACCESS_EXP_CLAIM = "axp"  # access-token expiry (epoch seconds), for cookie sync
_ROW_ID_CLAIM = "rid"  # idp_refresh_tokens row id

# Floor TTL when a backing row has already expired between read and mint (a
# race that should not normally happen; the token is still rejected on the
# next authenticate because its exp is in the past). Keeps create_jwe_token's
# expires_in positive.
_FLOOR_TTL = timedelta(seconds=1)


def _hash_api_key(plaintext: str) -> str:
    """The sha256 hex digest of an API-key plaintext — the persisted lookup key.

    Keys are 256-bit random (``secrets.token_urlsafe(32)``), so an unsalted
    sha256 is not brute-forceable; salting is unnecessary for high-entropy
    secrets and would break constant-time hash lookup by index.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class InvalidTokenError(Exception):
    """Raised internally when a token string cannot be authenticated."""


def _now() -> datetime:
    return datetime.now(UTC)


def _scopes_from_payload(payload: dict[str, object]) -> frozenset[str]:
    """Extract the scope set from a JWE payload's ``scp`` claim."""
    raw = payload.get(_SCOPE_CLAIM)
    if not isinstance(raw, str):
        return frozenset()
    return frozenset(s for s in raw.split() if s)


class TokenService:
    """Issue and validate JWE auth tokens, synced to federated IdP grants.

    Constructed per request with the request-scoped session; it holds no
    other mutable state. Encryption / encryption-key config come from the
    singletons, injectable for tests.

    Every minted access / cookie / refresh token derives its ``exp`` from the
    backing ``idp_access_tokens`` / ``idp_refresh_tokens`` row's expiry, so no
    client credential outlives the federated grant it backs. Token rotation
    (the IdP refresh grant) is performed by :class:`AuthService`; this service
    only mints and validates.
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

    # ------------------------------------------------------------------ #
    # Token issuance — expiries synced to the backing IdP rows.
    # ------------------------------------------------------------------ #

    async def create_access_token(self, user_id: uuid.UUID) -> str:
        """Mint an ACCESS_TOKEN JWE synced to the user's IdP access-token row.

        The token's ``exp`` equals the backing ``idp_access_tokens`` row's
        expiry (drift-adjusted IdP value), and carries the row's id (``aid``)
        so callers can correlate it with the federated grant. The app server
        never grants access beyond what the IdP sanctioned.
        """
        access_row = await self._load_access_row(user_id)
        return self._mint_access_token(user_id, access_row)

    async def create_cookie_token(self, user_id: uuid.UUID) -> str:
        """Mint a session COOKIE JWE synced to the user's IdP access-token row.

        Carries ``aid`` + ``axp`` (access-token row id + expiry) so the auth
        dependency can detect imminent expiry and trigger a server-side
        refresh. The cookie's own ``exp`` mirrors the access-token expiry.
        """
        access_row = await self._load_access_row(user_id)
        return self._mint_cookie_token(user_id, access_row)

    async def reissue_cookie(self, user_id: uuid.UUID) -> str:
        """Re-mint the session cookie. Synced to the current access-token row."""
        return await self.create_cookie_token(user_id)

    async def create_refresh_token(self, user_id: uuid.UUID) -> tuple[str, uuid.UUID]:
        """Mint an IDP_REFRESH_TOKEN JWE synced to the user's IdP refresh row.

        Returns (token, row_id). The token's ``exp`` equals the backing
        ``idp_refresh_tokens`` row's expiry and carries its id (``rid``) so
        the auth refresh endpoint can rotate it. Rotation is performed by
        :class:`AuthService.exchange_refresh_token`, not here.
        """
        refresh_row = await self._load_refresh_row_for_user(user_id)
        token = self._mint_refresh_token(user_id, refresh_row)
        return token, refresh_row.id

    async def create_api_key(
        self,
        user_id: uuid.UUID,
        *,
        name: str | None = None,
        enabled: bool = True,
        expires_at: datetime | None = None,
    ) -> tuple[str, ApiKey]:
        """Mint a long-lived opaque API key and persist its backing row.

        Returns (plaintext, row). The plaintext is a high-entropy
        ``secrets.token_urlsafe(32)`` string shown to the client exactly once;
        only its sha256 hash (``api_key_hash``) is persisted, so the key is not
        recoverable from the database. ``key_prefix`` stores a short, non-
        sensitive slice of the plaintext for UI display. API keys are the one
        credential whose lifetime is *not* IdP-synced (unless
        ``idp.sync_api_keys`` is set): they are user-managed service
        credentials; ``expires_at`` (if set) is the only cap.
        """
        plaintext = secrets.token_urlsafe(32)
        row = ApiKey(
            api_key_hash=_hash_api_key(plaintext),
            user_id=user_id,
            name=name,
            key_prefix=plaintext[:12],
            enabled=enabled,
            expires_at=expires_at,
        )
        self._session.add(row)
        await self._session.flush()
        return plaintext, row

    # ------------------------------------------------------------------ #
    # Authentication (token string -> AuthToken)
    # ------------------------------------------------------------------ #

    async def authenticate(
        self,
        token: str,
        *,
        allow_refresh: bool = False,
    ) -> AuthToken:
        """Decrypt *token* and return a validated :class:`AuthToken`.

        Raises :class:`InvalidTokenError` on any failure (bad JWE, expired,
        unknown type, revoked/disabled DB row, disabled user). Callers in the
        dependency layer catch this to produce a 401.
        """
        payload = self._decrypt(token)
        token_type = self._token_type(payload)
        if token_type is TokenType.IDP_REFRESH_TOKEN and not allow_refresh:
            # Refresh tokens are exchange-only credentials, not bearer tokens.
            raise InvalidTokenError("refresh token not valid for this endpoint")
        if token_type is TokenType.API_KEY:
            # Opaque API keys are resolved via authenticate_api_key, not the
            # JWE path. A JWE claiming ttyp=api_key is not a valid credential.
            raise InvalidTokenError("api key tokens are not JWE-encrypted")
        user_id = self._user_id(payload)
        jti = self._jti(payload)
        iat = self._iat(payload)
        exp = self._exp(payload)

        user = await self._load_user(user_id)
        if user is None or not user.enabled:
            raise InvalidTokenError("user not found or disabled")

        if exp <= _now():
            raise InvalidTokenError("token expired")

        enabled = True
        if token_type is TokenType.IDP_REFRESH_TOKEN:
            enabled = await self._idp_refresh_token_live(self._row_id(payload))

        return AuthToken(
            id=jti,
            user_id=user_id,
            created_at=iat,
            updated_at=iat,
            enabled=enabled and user.enabled,
            expires_at=exp,
            token_type=token_type,
            scopes=_scopes_from_payload(payload),
        )

    async def authenticate_api_key(self, plaintext: str) -> AuthToken:
        """Resolve an opaque API-key *plaintext* into an :class:`AuthToken`.

        Hashes the plaintext and looks the backing ``api_keys`` row up by
        ``api_key_hash``. Raises :class:`InvalidTokenError` if the key is
        unknown, disabled, or past its ``expires_at``. Unlike the JWE path,
        there is nothing to decrypt: the plaintext is the credential. Whether
        the resolved token's lifetime is gated by a federated session is
        decided by the auth dependency (``idp.sync_api_keys``), not here.
        """
        row = await self._load_api_key(plaintext)
        if row is None:
            raise InvalidTokenError("api key not recognized")
        if not row.enabled:
            raise InvalidTokenError("api key disabled")
        if row.expires_at is not None and row.expires_at <= _now():
            raise InvalidTokenError("api key expired")
        user = await self._load_user(row.user_id)
        if user is None or not user.enabled:
            raise InvalidTokenError("user not found or disabled")
        expires_at = row.expires_at or datetime.max.replace(tzinfo=UTC)
        return AuthToken(
            id=row.id,
            user_id=row.user_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
            enabled=True,
            expires_at=expires_at,
            token_type=TokenType.API_KEY,
            scopes=frozenset(),
        )

    # ------------------------------------------------------------------ #
    # Internals — minting (mirror AuthService's IdP-synced primitives).
    # ------------------------------------------------------------------ #

    def _mint_access_token(self, user_id: uuid.UUID, access_row: IdpAccessToken) -> str:
        """Mint ``ttyp: access_token`` with exp synced to the access row."""
        ttl = self._ttl_until(access_row.expires_at)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.ACCESS_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ACCESS_ID_CLAIM: str(access_row.id),
            },
            expires_in=ttl,
        )

    def _mint_cookie_token(self, user_id: uuid.UUID, access_row: IdpAccessToken) -> str:
        """Mint ``ttyp: cookie`` carrying aid + axp, exp synced to the access row."""
        ttl = self._ttl_until(access_row.expires_at)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.COOKIE.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ACCESS_ID_CLAIM: str(access_row.id),
                _ACCESS_EXP_CLAIM: int(access_row.expires_at.timestamp()),
            },
            expires_in=ttl,
        )

    def _mint_refresh_token(self, user_id: uuid.UUID, refresh_row: IdpRefreshToken) -> str:
        """Mint ``ttyp: idp_refresh_token`` carrying rid, exp synced to the refresh row."""
        ttl = self._ttl_until(refresh_row.expires_at)
        return self._enc.create_jwe_token(
            {
                _SUB_CLAIM: str(user_id),
                _TYP_CLAIM: TokenType.IDP_REFRESH_TOKEN.value,
                _JTI_CLAIM: str(uuid.uuid4()),
                _ROW_ID_CLAIM: str(refresh_row.id),
            },
            expires_in=ttl,
        )

    @staticmethod
    def _ttl_until(expires_at: datetime) -> timedelta:
        """Time from now until *expires_at*, floored at 1 second."""
        ttl = expires_at - _now()
        return ttl if ttl > _FLOOR_TTL else _FLOOR_TTL

    # ------------------------------------------------------------------ #
    # Internals — payload decode helpers.
    # ------------------------------------------------------------------ #

    def _decrypt(self, token: str) -> dict[str, object]:
        try:
            payload = self._enc.decrypt_jwe_token(token)
        except Exception as exc:
            raise InvalidTokenError("decryption failed") from exc
        if not isinstance(payload, dict):
            raise InvalidTokenError("invalid payload")
        return payload

    def _token_type(self, payload: dict[str, object]) -> TokenType:
        raw = payload.get(_TYP_CLAIM)
        if not isinstance(raw, str):
            raise InvalidTokenError("missing token type")
        try:
            return TokenType(raw)
        except ValueError as exc:
            raise InvalidTokenError("unknown token type") from exc

    def _user_id(self, payload: dict[str, object]) -> uuid.UUID:
        raw = payload.get(_SUB_CLAIM)
        if not isinstance(raw, str):
            raise InvalidTokenError("missing subject")
        try:
            return uuid.UUID(raw)
        except ValueError as exc:
            raise InvalidTokenError("invalid subject") from exc

    def _jti(self, payload: dict[str, object]) -> uuid.UUID:
        raw = payload.get(_JTI_CLAIM)
        if not isinstance(raw, str):
            raise InvalidTokenError("missing jti")
        try:
            return uuid.UUID(raw)
        except ValueError as exc:
            raise InvalidTokenError("invalid jti") from exc

    def _row_id(self, payload: dict[str, object]) -> uuid.UUID:
        raw = payload.get(_ROW_ID_CLAIM)
        if not isinstance(raw, str):
            raise InvalidTokenError("missing rid")
        try:
            return uuid.UUID(raw)
        except ValueError as exc:
            raise InvalidTokenError("invalid rid") from exc

    def _iat(self, payload: dict[str, object]) -> datetime:
        raw = payload.get(_IAT_CLAIM)
        if not isinstance(raw, int):
            raise InvalidTokenError("missing iat")
        return datetime.fromtimestamp(raw, tz=UTC)

    def _exp(self, payload: dict[str, object]) -> datetime:
        raw = payload.get(_EXP_CLAIM)
        if not isinstance(raw, int):
            # Tokens minted with no expiry (e.g. a no-expiry API key) never
            # expire by claim; sentinel datetime.max means the exp check passes.
            return datetime.max.replace(tzinfo=UTC)
        return datetime.fromtimestamp(raw, tz=UTC)

    # ------------------------------------------------------------------ #
    # Internals — row loaders.
    # ------------------------------------------------------------------ #

    async def _load_user(self, user_id: uuid.UUID) -> User | None:
        result = await self._session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def _load_access_row(self, user_id: uuid.UUID) -> IdpAccessToken:
        """Load the user's current IdP access-token row (most recent first).

        A user has one access row per federated login; the freshest backs the
        active session. Raises if none exists — minting cannot proceed
        without an IdP grant to sync to.
        """
        result = await self._session.execute(
            select(IdpAccessToken)
            .join(IdpRefreshToken, IdpAccessToken.refresh_token_id == IdpRefreshToken.id)
            .where(IdpRefreshToken.user_id == user_id)
            .order_by(IdpAccessToken.created_at.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise InvalidTokenError("no federated access token for user")
        return row

    async def _load_refresh_row_for_user(self, user_id: uuid.UUID) -> IdpRefreshToken:
        """Load the user's current IdP refresh-token row (most recent first)."""
        result = await self._session.execute(
            select(IdpRefreshToken)
            .where(IdpRefreshToken.user_id == user_id)
            .order_by(IdpRefreshToken.created_at.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise InvalidTokenError("no federated refresh token for user")
        return row

    async def _load_api_key(self, plaintext: str) -> ApiKey | None:
        """Look up the live ``api_keys`` row by sha256(plaintext)."""
        result = await self._session.execute(
            select(ApiKey).where(ApiKey.api_key_hash == _hash_api_key(plaintext))
        )
        return result.scalar_one_or_none()

    async def _idp_refresh_token_live(self, row_id: uuid.UUID) -> bool:
        row = await self._session.get(IdpRefreshToken, row_id)
        if row is None:
            return False
        return row.expires_at > _now()
