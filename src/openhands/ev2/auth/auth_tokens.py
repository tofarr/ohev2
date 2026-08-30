"""Token issuance, validation, and rotation for the auth feature.

:meth:`TokenService.authenticate` is the single entry point that converts a
JWE-encoded token string into an :class:`AuthToken`. Per-type validity:

* COOKIE / ACCESS_TOKEN — derived from the JWE claims alone; ``enabled`` is
  the user row's ``enabled`` flag (a disabled user cannot use any token).
* API_KEY — the ``oh_``-prefixed raw key's SHA-256 hash must match a live
  ``api_keys`` row, and the user must be enabled. The raw key is returned only
  once at create time and never stored.
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
import string
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

# --- API key value generation --------------------------------------------- #
# Raw API key values are ``oh_<base52(128 random bits)>``. base52 excludes
# visually-ambiguous characters so the key is transcribable; the ``oh_`` prefix
# lets the authenticator route the credential without trying JWE decryption.
_API_KEY_PREFIX = "oh_"
_API_KEY_RANDOM_BITS = 128  # 16 bytes of entropy
# Ambiguous characters removed from the alphanumeric set to form the base52
# alphabet (0/O, 1/I/l, 5/S, 8/B pair visual collisions).
_AMBIGUOUS = set("0Oo1IlB8S5")
_BASE52_ALPHABET = "".join(
    c
    for c in (string.digits + string.ascii_lowercase + string.ascii_uppercase)
    if c not in _AMBIGUOUS
)
assert len(_BASE52_ALPHABET) == 52
# Number of leading characters of the raw key persisted as the non-secret
# ``prefix`` for display in listings.
_API_KEY_PREFIX_DISPLAY_LEN = 12


class InvalidTokenError(Exception):
    """Raised internally when a token string cannot be authenticated."""


def _now() -> datetime:
    return datetime.now(UTC)


def _base52_encode(data: bytes) -> str:
    """Encode *data* as a base52 string over :data:`_BASE52_ALPHABET`."""
    num = int.from_bytes(data, "big")
    if num == 0:
        return _BASE52_ALPHABET[0]
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 52)
        chars.append(_BASE52_ALPHABET[rem])
    return "".join(reversed(chars))


def _generate_api_key_value() -> str:
    """Generate a raw API key value ``oh_<base52(128 random bits)>``."""
    raw = secrets.token_bytes(_API_KEY_RANDOM_BITS // 8)
    return _API_KEY_PREFIX + _base52_encode(raw)


def _hash_api_key(raw: str) -> str:
    """SHA-256 hex digest of the raw key value (stored for auth-time lookup)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _api_key_display_prefix(raw: str) -> str:
    """Non-secret leading prefix of the raw key, for display in listings."""
    return raw[:_API_KEY_PREFIX_DISPLAY_LEN]


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
        """Mint a long-lived API key and persist its backing row.

        Returns (raw_key, row). The raw key is ``oh_<base52(128 random bits)>``
        and is returned to the caller exactly once (at create time); it is never
        stored. The row persists only a SHA-256 ``key_hash`` of the raw value
        (for auth-time lookup) and a non-secret ``prefix`` for display. API keys
        are the one credential whose lifetime is *not* IdP-synced: they are
        user-managed service credentials.
        """
        raw_key = _generate_api_key_value()
        row = ApiKey(
            key_hash=_hash_api_key(raw_key),
            prefix=_api_key_display_prefix(raw_key),
            user_id=user_id,
            name=name,
            enabled=enabled,
            expires_at=expires_at,
        )
        self._session.add(row)
        await self._session.flush()
        return raw_key, row

    # ------------------------------------------------------------------ #
    # Authentication (token string -> AuthToken)
    # ------------------------------------------------------------------ #

    async def authenticate(
        self,
        token: str,
        *,
        allow_refresh: bool = False,
    ) -> AuthToken:
        """Resolve *token* into a validated :class:`AuthToken`.

        API keys (``oh_``-prefixed) are authenticated by hash lookup against the
        ``api_keys`` table; all other tokens are JWE-encrypted (cookie / access
        / refresh). Raises :class:`InvalidTokenError` on any failure (bad JWE,
        expired, unknown type, revoked/disabled DB row, disabled user). Callers
        in the dependency layer catch this to produce a 401.
        """
        if token.startswith(_API_KEY_PREFIX):
            return await self._authenticate_api_key(token)

        payload = self._decrypt(token)
        token_type = self._token_type(payload)
        if token_type is TokenType.API_KEY:
            # API keys are no longer carried in a JWE; only the ``oh_``-prefixed
            # plain value is accepted (handled above). Reject any legacy JWE that
            # claims the api_key type so it cannot bypass the row check.
            raise InvalidTokenError("api key not valid for this endpoint")
        if token_type is TokenType.IDP_REFRESH_TOKEN and not allow_refresh:
            # Refresh tokens are exchange-only credentials, not bearer tokens.
            raise InvalidTokenError("refresh token not valid for this endpoint")
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

    async def _authenticate_api_key(self, raw_key: str) -> AuthToken:
        """Authenticate an ``oh_``-prefixed API key by hash lookup.

        Looks up the backing row by the SHA-256 of the raw key. A missing or
        expired row raises :class:`InvalidTokenError` (the key is simply
        invalid). A present but disabled row resolves to an :class:`AuthToken`
        with ``enabled=False`` so the caller surfaces a 401 without leaking
        whether the key exists. The token's ``exp`` mirrors the row's
        ``expires_at`` (or ``datetime.max`` for a no-expiry key).
        """
        row = await self._load_api_key_row(_hash_api_key(raw_key))
        if row is None:
            raise InvalidTokenError("unknown api key")
        now = _now()
        exp = row.expires_at if row.expires_at is not None else datetime.max.replace(tzinfo=UTC)
        if exp <= now:
            raise InvalidTokenError("api key expired")

        user = await self._load_user(row.user_id)
        if user is None or not user.enabled:
            raise InvalidTokenError("user not found or disabled")

        return AuthToken(
            id=row.id,
            user_id=row.user_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
            enabled=row.enabled and user.enabled,
            expires_at=exp,
            token_type=TokenType.API_KEY,
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

    async def _load_api_key_row(self, key_hash: str) -> ApiKey | None:
        """Load an API-key backing row by its key hash (or ``None`` if absent)."""
        result = await self._session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
        return result.scalar_one_or_none()

    async def _idp_refresh_token_live(self, row_id: uuid.UUID) -> bool:
        row = await self._session.get(IdpRefreshToken, row_id)
        if row is None:
            return False
        return row.expires_at > _now()
