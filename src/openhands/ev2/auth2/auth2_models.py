"""ORM models for the federated OAuth (auth2) feature.

auth2 delegates authentication to an external identity provider (OIDC/OAuth2).
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

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

# All auth2 timestamps are timezone-aware (TIMESTAMPTZ) so comparisons against
# datetime.now(UTC) never mix naive and aware values.
_TZ = DateTime(timezone=True)


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
    against the redirect_uri supplied at ``/auth2/authorize``.
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
