"""ORM models owned by the SQL-backed secrets service.

These tables are internal to :class:`SqlSecretsService` (see
:mod:`sql_secrets_service`) — the default :class:`SecretsService`
implementation. The service translates rows to the provider-neutral Pydantic
:class:`openhands.ev2.secret.secret_models.Secret` before returning, so no
other module should consume these ORM classes directly. (The exceptions are
schema/migration wiring — Alembic env and test metadata registration — and
the ACL-prune sweep, which resolves the canonical id space for the
``secret_permission`` / ``secret_value_permission`` columns.)

Tables:

* :class:`SqlSecret` — the metadata row. It never stores a value itself; the
  sensitive payload lives in :class:`SqlSecretDetail`. ``code`` is unique and
  matches ``[A-Za-z0-9_]+`` (validated in the schema), so a secret can be
  referenced by a stable human-readable key as well as by id. The optional
  ``creator_id`` records the creating user for ownership-based access control.
* :class:`SqlSecretDetail` — the encrypted plaintext (1:1 with
  :class:`SqlSecret`).

The secret tables never expose their sensitive values through the ``/secrets``
CRUD endpoints; the only reveal path is the ``/secret-values`` projection,
governed by the separate ``secret_value_permission`` column (AGENTS.md §12).
"""

from __future__ import annotations

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


class SqlSecret(Base):
    """The secret's metadata row.

    The sensitive payload is NOT on this table — it lives in
    :class:`SqlSecretDetail`.
    """

    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
    )
    creator_id: Mapped[uuid.UUID | None] = mapped_column(
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


class SqlSecretDetail(Base):
    """The encrypted plaintext for a secret. 1:1 with SqlSecret.

    The ``value`` column stores the secret payload encrypted at rest (JWE
    ciphertext); the plaintext is never persisted. ``secret_id`` is unique so
    each secret has at most one detail row, and deleting the parent
    :class:`SqlSecret` cascades to the detail row.
    """

    __tablename__ = "secret_details"
    __table_args__ = ({"comment": "Encrypted plaintext for secrets"},)

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
