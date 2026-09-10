"""ORM models for the typed secret feature.

Tables:

* :class:`Secret` — the umbrella table carrying a type discriminator
  (``static`` or ``oauth``) and metadata only. It never stores a value itself;
  the sensitive payload lives in a type-specific detail table. ``code`` is
  unique and matches ``[A-Za-z0-9_]+`` (validated in the schema), so a secret
  can be referenced by a stable human-readable key as well as by id. The
  optional ``user_id`` records the creating user for ownership-based access
  control.
* :class:`StaticSecretDetail` — the encrypted plaintext for a ``type='static'``
  secret (1:1 with :class:`Secret`). Future ``oauth_*`` detail tables will hold
  access/refresh tokens.

The typed secret tables (``secrets``, ``static_secret_details``) never expose
their sensitive values through their own CRUD endpoints; the only reveal path
is the ``/secret-values`` projection, governed by the separate
``secret_value_permission`` column (AGENTS.md §12).

The :class:`SecretValueAccess` policy for the ``/secret-values`` projection
lives in ``secret_security``; this module only defines the ORM tables.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

# All secret timestamps are timezone-aware (TIMESTAMPTZ) so comparisons against
# datetime.now(UTC) never mix naive and aware values (mirrors auth_models).
_TZ = DateTime(timezone=True)


class SecretType(enum.StrEnum):
    """Discriminator for the type-specific detail table holding the payload.

    ``STATIC`` — the plaintext lives in :class:`StaticSecretDetail`.
    ``OAUTH`` — reserved; no detail table exists yet (OAuth token refresh is
    out of scope for the typed-secrets schema groundwork).
    """

    STATIC = "static"
    OAUTH = "oauth"


class Secret(Base):
    """The umbrella secret row, carrying a type discriminator and metadata.

    The sensitive payload is NOT on this table — it lives in a type-specific
    detail table (e.g. :class:`StaticSecretDetail`). The ``/secrets`` surface
    returns metadata only; decrypted values are revealed solely through the
    ``/secret-values`` projection (AGENTS.md §12).
    """

    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    type: Mapped[SecretType] = mapped_column(
        String(16),
        default=SecretType.STATIC,
        server_default=SecretType.STATIC.value,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        default=None,
        nullable=True,
        comment="The user who created this secret; null when creator is unknown.",
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


class StaticSecretDetail(Base):
    """The encrypted plaintext for a ``type='static'`` secret. 1:1 with Secret.

    The ``value`` column stores the secret payload encrypted at rest (JWE
    ciphertext); the plaintext is never persisted. ``secret_id`` is unique so
    each static secret has at most one detail row, and deleting the parent
    :class:`Secret` cascades to the detail row.
    """

    __tablename__ = "static_secret_details"
    __table_args__ = ({"comment": "Encrypted plaintext for static secrets"},)

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    secret_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("secrets.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    # Encrypted value (JWE ciphertext). Text so arbitrarily large secrets
    # (keys, certs) fit without a fixed-length ceiling.
    value: Mapped[str] = mapped_column(Text)
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
