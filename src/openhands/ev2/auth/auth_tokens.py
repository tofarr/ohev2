"""Token issuance, validation, and rotation for the auth feature.

:meth:`TokenService.authenticate` is the single entry point that converts a
JWE-encoded token string into an :class:`AuthToken`. Per-type validity:

* COOKIE / ACCESS_TOKEN — derived from the JWE claims alone; ``enabled`` is
  the user row's ``enabled`` flag (a disabled user cannot use any token).
* API_KEY — the token's ``jti`` must match a live ``api_keys`` row, and the
  user must be enabled.
* REFRESH_TOKEN — the token's ``jti`` must match a live ``refresh_tokens``
  row, and the user must be enabled. (Refresh tokens are not accepted by
  ``authenticate`` for general requests; they are exchanged at the refresh
  endpoint.)

Cookie re-minting (sliding session) and refresh-token rotation are handled
here so the logic is testable without HTTP. This module is the canonical home
for token primitives formerly in the legacy ``auth`` package.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_models import ApiKey, AuthToken, RefreshToken, TokenType
from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.user.user_models import User

_SUB_CLAIM = "sub"
_TYP_CLAIM = "ttyp"
_JTI_CLAIM = "jti"
_IAT_CLAIM = "iat"
_EXP_CLAIM = "exp"
_SCOPE_CLAIM = "scp"


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
    """Issue, validate, and rotate JWE auth tokens.

    The service is constructed per request with the request-scoped session; it
    holds no other mutable state. Encryption/encryption-key config comes from
    the singletons, injectable for tests.
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
    # Token issuance
    # ------------------------------------------------------------------ #

    def create_cookie_token(self, user_id: uuid.UUID) -> str:
        """Mint a short-lived COOKIE token whose exp = now + cookie timeout."""
        return self._mint(user_id, TokenType.COOKIE, self._cookie_ttl())

    def create_access_token(self, user_id: uuid.UUID) -> str:
        """Mint a short-lived ACCESS_TOKEN (OAuth2 access token)."""
        return self._mint(user_id, TokenType.ACCESS_TOKEN, self._access_ttl())

    async def create_refresh_token(self, user_id: uuid.UUID) -> tuple[str, uuid.UUID]:
        """Mint a REFRESH_TOKEN and persist its backing row.

        Returns (token, jti). The row's ``expires_at`` is the sliding window
        added to now, capped by the absolute refresh TTL.
        """
        jti = uuid.uuid4()
        expires_at = _now() + self._refresh_sliding()
        row = RefreshToken(jti=jti, user_id=user_id, expires_at=expires_at)
        self._session.add(row)
        await self._session.flush()
        token = self._mint(user_id, TokenType.REFRESH_TOKEN, self._refresh_sliding(), jti=jti)
        return token, jti

    async def create_api_key(
        self,
        user_id: uuid.UUID,
        *,
        name: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[str, ApiKey]:
        """Mint a long-lived API_KEY token and persist its backing row.

        Returns (token, row). The token's JWE ``exp`` mirrors the row's
        ``expires_at`` (or is omitted entirely when the key never expires).
        """
        jti = uuid.uuid4()
        row = ApiKey(jti=jti, user_id=user_id, name=name, expires_at=expires_at)
        self._session.add(row)
        await self._session.flush()
        ttl = None
        if expires_at is not None:
            ttl = expires_at - _now()
            if ttl.total_seconds() <= 0:
                ttl = None
        token = self._mint(
            user_id,
            TokenType.API_KEY,
            ttl,
            jti=jti,
            name=name,
        )
        return token, row

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
        if token_type is TokenType.REFRESH_TOKEN and not allow_refresh:
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
        if token_type is TokenType.API_KEY:
            enabled = await self._api_key_live(jti)
        elif token_type is TokenType.REFRESH_TOKEN:
            enabled = await self._refresh_token_live(jti)

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

    # ------------------------------------------------------------------ #
    # Refresh-token rotation (sliding)
    # ------------------------------------------------------------------ #

    async def refresh(self, refresh_token: str) -> tuple[str, str, uuid.UUID]:
        """Exchange a refresh token for a new access/refresh pair.

        Invalidates the presented token's row and mints a successor with a
        fresh ``jti`` whose expiry is ``min(now + sliding, first_created +
        absolute_ttl)``. Returns (access_token, refresh_token, user_id).
        """
        payload = self._decrypt(refresh_token)
        if self._token_type(payload) is not TokenType.REFRESH_TOKEN:
            raise InvalidTokenError("not a refresh token")
        jti = self._jti(payload)
        user_id = self._user_id(payload)

        old = await self._load_refresh_row(jti)
        if old is None or not old.enabled or old.expires_at <= _now():
            raise InvalidTokenError("refresh token revoked or expired")

        successor_jti = uuid.uuid4()
        old.enabled = False
        old.replaced_by = successor_jti

        cap = old.created_at + timedelta(seconds=self._cfg.auth_refresh_token_ttl_seconds)
        sliding = _now() + self._refresh_sliding()
        new_expires_at = sliding if sliding <= cap else cap

        new_row = RefreshToken(
            jti=successor_jti,
            user_id=user_id,
            expires_at=new_expires_at,
        )
        self._session.add(new_row)
        await self._session.flush()

        access = self.create_access_token(user_id)
        refresh = self._mint(
            user_id,
            TokenType.REFRESH_TOKEN,
            new_expires_at - _now(),
            jti=successor_jti,
        )
        return access, refresh, user_id

    # ------------------------------------------------------------------ #
    # Cookie sliding re-mint
    # ------------------------------------------------------------------ #

    def reissue_cookie(self, user_id: uuid.UUID) -> str:
        """Mint a fresh COOKIE token with expiry = now + cookie timeout."""
        return self.create_cookie_token(user_id)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _mint(
        self,
        user_id: uuid.UUID,
        token_type: TokenType,
        expires_in: timedelta | None,
        *,
        jti: uuid.UUID | None = None,
        name: str | None = None,
    ) -> str:
        payload: dict[str, object] = {
            _SUB_CLAIM: str(user_id),
            _TYP_CLAIM: token_type.value,
            _JTI_CLAIM: str(jti or uuid.uuid4()),
        }
        if name is not None:
            payload["name"] = name
        return self._enc.create_jwe_token(payload, expires_in=expires_in)

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

    async def _load_user(self, user_id: uuid.UUID) -> User | None:
        result = await self._session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def _api_key_live(self, jti: uuid.UUID) -> bool:
        result = await self._session.execute(
            select(ApiKey).where(ApiKey.jti == jti, ApiKey.enabled.is_(True))
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False
        return not (row.expires_at is not None and row.expires_at <= _now())

    async def _refresh_token_live(self, jti: uuid.UUID) -> bool:
        row = await self._load_refresh_row(jti)
        if row is None or not row.enabled:
            return False
        return row.expires_at > _now()

    async def _load_refresh_row(self, jti: uuid.UUID) -> RefreshToken | None:
        result = await self._session.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        return result.scalar_one_or_none()

    def _cookie_ttl(self) -> timedelta:
        return timedelta(seconds=self._cfg.auth_cookie_timeout_seconds)

    def _access_ttl(self) -> timedelta:
        return timedelta(seconds=self._cfg.auth_access_token_ttl_seconds)

    def _refresh_sliding(self) -> timedelta:
        return timedelta(seconds=self._cfg.auth_refresh_token_sliding_seconds)
