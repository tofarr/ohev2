"""ORM models for the secret provider feature (AGENTS.md §12).

Two tables back the multi-provider, retrieval-oriented secret model:

* :class:`SecretProvider` — a governed CRUD row describing one secret source.
  ``kind`` selects the :class:`SecretProvider` ABC implementation
  (``static``, ``aws_sm``, ``onepassword``, ...); ``data`` is provider-specific
  config (vault id, name prefix, credentials, ...) serialized per the §13
  standard. Providers are themselves a governed resource (``secret_provider_permission``),
  so external vaults can be registered/revoked through the API without a
  second admin surface.
* :class:`StaticSecret` — the backing store for the ``kind="static"`` provider:
  a DB-managed secret (encrypted ``value`` at rest) with optional validity
  bounds. ``name`` matches ``[A-Z_][A-Z0-9_]*`` (env-var compatible) and is the
  human-readable handle; the provider derives ``internal_id`` as the stringified
  row UUID at read time (it is not stored as an explicit column).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)

# The supported ``secret_providers.kind`` discriminator for the DB-backed store.
STATIC_PROVIDER_KIND = "static"


class SecretProvider(Base):
    """A governed secret-source configuration row.

    ``kind`` + ``data`` resolve to a concrete :class:`SecretProvider`
    implementation at request time (see :mod:`secret_provider_registry`).
    ``data`` may hold credentials (a 1Password service-account token, an AWS
    access key); it is serialized through the §13 context standard so the
    column stores JWE ciphertext when the caller passes an encryption service.
    """

    __tablename__ = "secret_providers"
    __table_args__ = {"comment": "Governed secret-source configurations (retrieval-only)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    kind: Mapped[str] = mapped_column(
        String(64),
        comment="Discriminator selecting the SecretProvider implementation (static, aws_sm, onepassword, ...).",
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Provider-specific configuration (vault id, name prefix, credentials).",
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


class StaticSecret(Base):
    """A DB-managed secret backing the ``kind="static"`` provider.

    The sensitive ``value`` is encrypted at rest (JWE ciphertext). ``name`` is
    unique and matches ``[A-Z_][A-Z0-9_]*``; it is the human-readable handle,
    while ``internal_id`` (the addressable id) is the stringified row UUID,
    generated on the :class:`SecretValue` at read time — not stored here.
    ``valid_at`` / ``expires_at`` are nullable; ``None`` means "always valid".
    """

    __tablename__ = "static_secrets"
    __table_args__ = {"comment": "DB-backed secret store for the static provider"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        comment="Env-var-compatible handle [A-Z_][A-Z0-9_]*; unique.",
    )
    # Encrypted value (JWE ciphertext). Text so arbitrarily large secrets
    # (keys, certs) fit without a fixed-length ceiling.
    value: Mapped[str] = mapped_column(
        Text,
        comment="Encrypted plaintext (JWE ciphertext) of the secret value.",
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    valid_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        default=None,
        nullable=True,
        comment="Start of validity; null = always valid.",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        default=None,
        nullable=True,
        comment="End of validity; null = never expires.",
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
