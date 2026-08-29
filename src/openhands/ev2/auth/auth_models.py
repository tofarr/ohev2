"""ORM models for the federated OAuth (auth) feature.

auth delegates authentication to an external identity provider (OIDC/OAuth2).
The project acts as a federated proxy: clients authorize against the IdP, the
callback exchanges the code for IdP tokens, and the project mints its own
JWE access tokens and DB-backed refresh tokens for clients to use.

Tables:

* ``idp_refresh_tokens`` — the encrypted IdP refresh token plus its expiry.
  Expiry is the IdP refresh-token expiry (drift-adjusted); when the IdP does
  not advertise one, ``idp_refresh_token_expires_in`` is the fallback.
* ``idp_access_tokens`` — the encrypted IdP access token plus its expiry,
  referencing the refresh row (1:1). Expiry is the IdP access-token expiry
  (drift-adjusted); when the IdP does not advertise one,
  ``idp_access_token_expires_in`` is the fallback. The local minted access
  token (JWE handed to clients) has its ``exp`` synced to this row's expiry so
  a client token never outlives the federated credential backing it.
* ``oauth_clients`` — clients registered to use this project as an OAuth
  provider. Each has a client_id / client_secret (encrypted) and a set of
  permitted redirect URIs (``oauth_client_redirect_uris``), which may contain
  wildcard segments.
* ``oauth_client_redirect_uris`` — the allow-list of redirect URIs for a
  client. Wildcards (``*``) are matched segment-wise.

The ``users.idp_user_id`` column (added in the same migration) stores the
stable IdP subject used to look up the local user on callback.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

# All auth timestamps are timezone-aware (TIMESTAMPTZ) so comparisons against
# datetime.now(UTC) never mix naive and aware values.
_TZ = DateTime(timezone=True)


class TokenType(enum.StrEnum):
    """The kind of credential a token represents.

    COOKIE and ACCESS_TOKEN are short-lived JWE tokens validated against the
    user row only. API_KEY and REFRESH_TOKEN are additionally validated
    against their DB rows.
    """

    COOKIE = "cookie"
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    # auth (federated OAuth) refresh token. Exchange-only: never accepted as a
    # bearer credential by TokenService.authenticate. Handled by the auth
    # refresh endpoint, which validates it against the idp_refresh_tokens row.
    IDP_REFRESH_TOKEN = "idp_refresh_token"


class AuthToken(BaseModel):
    """The decrypted view of a credential, normalized across all flows.

    ``enabled`` is resolved by :class:`TokenService` from the user row (and the
    token's DB row for API_KEY/REFRESH_TOKEN).
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    enabled: bool
    expires_at: datetime
    token_type: TokenType
    # OAuth/OIDC scopes granted to the token (empty for non-OAuth tokens like
    # API keys). Carried in the JWE ``scp`` claim so the UserInfo endpoint and
    # other consumers can gate claims without re-decrypting.
    scopes: frozenset[str] = frozenset()


class ApiKey(Base):
    """A revocable backing row for an API-key credential.

    The row shares its ``jti`` with the API-key JWE token minted for it; a
    token whose jti has no live row is rejected even if the JWE itself is
    decryptable and unexpired.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    jti: Mapped[uuid.UUID] = mapped_column(unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str | None] = mapped_column(default=None, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    expires_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        default=None,
        nullable=True,
        comment="Null means the API key never expires on its own.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class RefreshToken(Base):
    """A backing row for a refresh-token credential.

    Rotation invalidates the row (``enabled = False``) and mints a successor
    token with a fresh ``jti``. ``expires_at`` is the absolute cap of the
    sliding window: each rotation extends a *new* row's expiry to
    ``min(now + sliding_window, first_issued_at + absolute_ttl)``.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    jti: Mapped[uuid.UUID] = mapped_column(unique=True, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        _TZ,
        comment="Absolute cap of the sliding refresh window.",
    )
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        default=None,
        nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class IdpRefreshToken(Base):
    """An encrypted IdP refresh token persisted for a local user.

    The ``refresh_token`` column holds the IdP's refresh token encrypted by the
    encryption service (AGENTS.md §9 — sensitive data at rest). ``expires_at``
    is the IdP refresh token's expiry, adjusted by ``idp_expire_drift_tolerance``;
    when the IdP advertises no refresh-token expiry, ``idp_refresh_token_expires_in``
    is the fallback. When this row expires the user must re-authenticate.
    """

    __tablename__ = "idp_refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    # Encrypted IdP refresh token (JWE ciphertext).
    refresh_token: Mapped[str] = mapped_column(String(8192))
    expires_at: Mapped[datetime] = mapped_column(_TZ)
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class IdpAccessToken(Base):
    """An encrypted IdP access token persisted for a local user.

    References its backing :class:`IdpRefreshToken` (1:1, cascade delete).
    ``access_token`` holds the IdP access token encrypted at rest.
    ``expires_at`` is the IdP access-token expiry (drift-adjusted); when the
    IdP advertises no access-token expiry, ``idp_access_token_expires_in`` is
    the fallback. The local JWE access token handed to clients carries this
    row's id and has its ``exp`` synced to ``expires_at``.
    """

    __tablename__ = "idp_access_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    refresh_token_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("idp_refresh_tokens.id", ondelete="CASCADE"),
        index=True,
    )
    # Encrypted IdP access token (JWE ciphertext).
    access_token: Mapped[str] = mapped_column(String(8192))
    expires_at: Mapped[datetime] = mapped_column(_TZ)
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class OAuthClient(Base):
    """A client registered to use this project as an OAuth provider.

    The ``client_secret`` is encrypted at rest (encryption service). A client
    has zero or more permitted redirect URIs (``OAuthClientRedirectUri``).
    """

    __tablename__ = "oauth_clients"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    client_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    # Encrypted client secret (JWE ciphertext).
    client_secret: Mapped[str] = mapped_column(String(8192))
    name: Mapped[str | None] = mapped_column(String(255), default=None, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class OAuthClientRedirectUri(Base):
    """A permitted redirect URI for an OAuth client.

    The ``uri`` may contain wildcard segments (``*``) matched segment-wise
    against the redirect_uri supplied at ``/auth/authorize``.
    """

    __tablename__ = "oauth_client_redirect_uris"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"),
        index=True,
    )
    uri: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
