"""ORM models for the federated OAuth (auth2) feature.

auth2 delegates authentication to an external identity provider (OIDC/OAuth2).
The project acts as a federated proxy: clients authorize against the IdP, the
callback exchanges the code for IdP tokens, and the project mints its own
JWE access tokens and DB-backed refresh tokens for clients to use.

Tables:

* ``idp_refresh_tokens`` — the encrypted IdP refresh token plus its expiry.
  The IdP access token is intentionally *not* persisted: it is short-lived and
  self-contained, so a refresh (which requires only the refresh token) is all
  the server needs to obtain a fresh access token from the IdP.
* ``oauth_clients`` — clients registered to use this project as an OAuth
  provider. Each has a client_id / client_secret (encrypted) and a set of
  permitted redirect URIs (``oauth_client_redirect_uris``), which may contain
  wildcard segments.
* ``oauth_client_redirect_uris`` — the allow-list of redirect URIs for a
  client. Wildcards (``*``) are matched segment-wise.
* ``oauth_client_allowed_origins`` — the allow-list of browser origins
  (scheme://host[:port]) permitted to initiate a ``response_type=cookie``
  flow. When non-empty, the authorize endpoint rejects cookie-flow requests
  whose ``Origin``/``Referer`` does not match (XSRF defense).

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
    is the IdP refresh token's expiry, adjusted by ``idp_expire_drift_tolerance``.
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


class OAuthClientAllowedOrigin(Base):
    """A permitted browser origin for an OAuth client (XSRF defense).

    The ``origin`` is a serialized origin (scheme://host[:port], per RFC 6454)
    matched case-sensitively against the ``Origin``/``Referer`` of the browser
    request that initiates a ``response_type=cookie`` flow. When a client has at
    least one allowed origin configured, the authorize endpoint only starts the
    cookie flow for a request whose browser origin matches; an empty list means
    no origin restriction (the redirect-URI allow-list alone governs the flow).
    """

    __tablename__ = "oauth_client_allowed_origins"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"),
        index=True,
    )
    origin: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
    )
