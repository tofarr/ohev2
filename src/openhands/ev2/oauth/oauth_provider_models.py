"""ORM model for the governed ``OAuthProvider`` resource (AGENTS.md §12, §11).

An :class:`OAuthProvider` is a governed CRUD row registering an external
OAuth/OIDC provider (GitHub, GitLab, Bitbucket, Jira, Linear, …) whose tokens
can be obtained for downstream use. It is modeled on the :class:`IdpConfig`
shape but is a **separate, multi-instance, governed CRUD resource**; the
existing login IdP stays as-is (single, env-configured). IdP = who you log in
*as*; OAuthProvider = whose tokens you can obtain *for downstream use*.

The ``client_secret`` is encrypted at rest (JWE ciphertext) and follows the
§13 serialization standard: masked ``**********`` on read, plaintext only with
``expose_secrets``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class OAuthProvider(Base):
    """A governed external OAuth/OIDC provider configuration row.

    ``client_secret`` stores JWE ciphertext (decrypted on read via the
    encryption service). The remaining fields mirror :class:`IdpConfig` so a
    provider row is self-contained: the OAuth login/consent flow (sub-issue
    #144) reads from this row rather than from the env-configured login IdP.
    """

    __tablename__ = "oauth_providers"
    __table_args__ = {"comment": "Governed external OAuth provider configurations"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        comment="Human-readable provider name; unique.",
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    url: Mapped[str] = mapped_column(
        String(2048),
        comment="Base URL of the external OAuth/OIDC provider.",
    )
    client_id: Mapped[str] = mapped_column(
        String(255),
        comment="Client id registered at the external provider.",
    )
    # Encrypted client secret (JWE ciphertext).
    client_secret: Mapped[str] = mapped_column(
        Text,
        comment="Encrypted client secret (JWE ciphertext).",
    )
    scopes: Mapped[list[str]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="OAuth scopes requested from the external provider.",
    )
    user_id_field: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        nullable=True,
        comment="Claim name for the stable provider subject; defaults to 'sub'.",
    )
    email_field: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        nullable=True,
        comment="Claim name for user email; defaults to 'email'.",
    )
    role_field: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        nullable=True,
        comment="Claim name for role information (reserved for future use).",
    )
    expire_drift_tolerance: Mapped[int] = mapped_column(
        Integer,
        default=60,
        comment="Seconds subtracted from token expiries to guard against clock drift.",
    )
    authorize_path: Mapped[str] = mapped_column(
        String(255),
        default="/authorize",
        comment="Path appended to url for the authorization endpoint.",
    )
    token_path: Mapped[str] = mapped_column(
        String(255),
        default="/token",
        comment="Path appended to url for the token exchange endpoint.",
    )
    refresh_path: Mapped[str] = mapped_column(
        String(255),
        default="/token",
        comment="Path appended to url for the refresh-token endpoint.",
    )
    revocation_path: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        nullable=True,
        comment="Path appended to url for the RFC 7009 revocation endpoint.",
    )
    access_token_expires_in: Mapped[int] = mapped_column(
        Integer,
        default=900,
        comment="Fallback access-token lifetime (seconds) when the provider omits one.",
    )
    refresh_token_expires_in: Mapped[int] = mapped_column(
        Integer,
        default=2_592_000,
        comment="Fallback refresh-token lifetime (seconds) when the provider omits one.",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default="true",
        comment="Whether new sessions can be created against this provider.",
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
