"""ORM models for the secret feature.

Two tables:

* :class:`Secret` — a named secret identified by a stable ``code`` (letters,
  digits, underscores; like a feature-flag key). The ``value`` is the secret
  payload encrypted at rest via the encryption service (AGENTS.md §9 —
  sensitive data at rest), mirroring how OAuth client secrets are stored. The
  ``user_id`` records who created the secret.
* :class:`RoleSecret` — the per-role grant link table (``role_secrets``). A
  row grants a :class:`Role` access to a :class:`Secret` for the read/update/
  delete actions via the ``read_enabled`` / ``update_enabled`` /
  ``delete_enabled`` flags. The :class:`SecretAccess` permission policy on
  the ``secret_permission`` column of :class:`Role` reduces read/update/delete
  to a filter that joins this table, so a principal may read/update/delete a
  secret only when one of their roles has a matching enabled row here.
  ``CREATE`` is gated by the policy alone (a role carrying ``SecretAccess`` or
  ``Permitted`` may create any secret); there is no create flag because there
  is no secret id to grant against until it exists.

The :class:`SecretAccess` policy and its :class:`SecretAccessFilter` live in
``secret_security``; this module only defines the ORM tables.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base

# All secret timestamps are timezone-aware (TIMESTAMPTZ) so comparisons against
# datetime.now(UTC) never mix naive and aware values (mirrors auth_models).
_TZ = DateTime(timezone=True)


class Secret(Base):
    """A named secret identified by a stable ``code``.

    The ``value`` column stores the secret payload encrypted at rest (JWE
    ciphertext); the plaintext is never persisted. ``code`` is unique and
    matches ``[A-Za-z0-9_]+`` (validated in the schema), so a secret can be
    referenced by a stable human-readable key as well as by id.
    """

    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Encrypted value (JWE ciphertext). Text so arbitrarily large secrets
    # (keys, certs) fit without a fixed-length ceiling.
    value: Mapped[str] = mapped_column(Text)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        default=None,
        nullable=True,
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


class RoleSecret(Base):
    """A per-role grant of access to a :class:`Secret`.

    A row links a :class:`Role` to a :class:`Secret` and carries three
    independent action flags: ``read_enabled``, ``update_enabled``, and
    ``delete_enabled``. The :class:`SecretAccess` permission policy reduces a
    read/update/delete action to a filter that admits a secret only when one
    of the principal's roles has a row here with the matching flag enabled.
    The ``(role_id, secret_id)`` pair is unique so a role can be granted a
    secret at most once; toggle the flags to change what the role may do.
    """

    __tablename__ = "role_secrets"
    __table_args__ = (
        UniqueConstraint("role_id", "secret_id", name="uq_role_secrets_role_id_secret_id"),
        {"comment": "Per-role grants of access to secrets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        index=True,
    )
    secret_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("secrets.id", ondelete="CASCADE"),
        index=True,
    )
    read_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    update_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    delete_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
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
