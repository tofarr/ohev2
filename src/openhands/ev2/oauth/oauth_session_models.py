"""ORM model for the governed ``OAuthSession`` resource (AGENTS.md §12, §11).

An :class:`OAuthSession` holds one user's encrypted access + refresh tokens for
one :class:`OAuthProvider`, produced by the login/consent flow (sub-issue #144).
The agent server inside a sandbox consumes these tokens via the secrets surface
(sub-issue #145); this table stores them.

Both ``access_token`` and ``refresh_token`` are encrypted at rest (JWE
ciphertext). ``access_token_expires_at`` and ``refresh_token_expires_at`` are
drift-adjusted expiries sourced from the provider response. The
``tolerate_invalid`` flag controls the failure mode when the session is
unrecoverable (refresh token expired/revoked): ``true`` → omit from results
(no error); ``false`` → surface an error.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class OAuthSession(Base):
    """A governed row holding one user's tokens for one :class:`OAuthProvider`.

    ``oauth_provider_id`` is ``RESTRICT`` so a provider with sessions cannot
    be deleted without first removing the sessions. ``creator_id`` is
    ``CASCADE`` so deleting the user removes their sessions.
    """

    __tablename__ = "oauth_sessions"
    __table_args__ = {"comment": "Per-user OAuth tokens for a governed provider"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    oauth_provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_providers.id", ondelete="RESTRICT"),
        index=True,
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    # Encrypted provider refresh token (JWE ciphertext).
    refresh_token: Mapped[str] = mapped_column(
        Text,
        comment="Encrypted provider refresh token (JWE ciphertext).",
    )
    # Encrypted provider access token (JWE ciphertext).
    access_token: Mapped[str] = mapped_column(
        Text,
        comment="Encrypted provider access token (JWE ciphertext).",
    )
    access_token_expires_at: Mapped[datetime] = mapped_column(
        _TZ,
        comment="Drift-adjusted access-token expiry.",
    )
    refresh_token_expires_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        default=None,
        nullable=True,
        comment="Drift-adjusted refresh-token expiry; null when the provider did not advertise one.",
    )
    tolerate_invalid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
        comment="When true, an unrecoverable session is silently omitted rather than erroring.",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        comment="Whether this session is eligible for token retrieval.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )
