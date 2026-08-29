"""ORM models for the feature_flag feature.

Two tables:

* :class:`FeatureFlag` — a named on/off switch keyed by a human-readable string
  id (uppercase letters, digits, and underscores). Carries an ``enabled`` flag
  and an optional ``description``. The id is the primary key (supplied by the
  caller, not server-generated), so feature-flag references are stable and
  readable in configuration/code.
* :class:`FeatureFlagRole` — a link table assigning a :class:`Role` to a
  feature flag. The presence of a row *overrides* the feature flag's
  ``enabled`` setting for any user holding that role: the flag is considered
  enabled for such a user regardless of the flag's global ``enabled`` value.
  Immutable (no update) — delete and re-create to change, mirroring
  ``user_roles``. Unique on ``(feature_flag_id, role_id)``.

The ``feature_flag_permission`` and ``feature_flag_role_permission`` columns on
:class:`Role` (and their entries in ``ROLE_ENTITY_COLUMNS``) govern these
resources; see AGENTS.md §11.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base

# Max length for a feature-flag id. The id charset is restricted to uppercase
# letters, digits, and underscores (validated in the schema layer); the column
# width is a generous cap, not a meaningful business limit.
_FEATURE_FLAG_ID_LENGTH = 128


class FeatureFlag(Base):
    """A named on/off switch keyed by a human-readable string id.

    The ``id`` is the primary key and is supplied by the caller (not
    server-generated) so flag references stay stable and readable. The
    charset is restricted to ``[A-Z0-9_]`` (validated in the Pydantic schemas).
    ``enabled`` is the global default; per-role overrides live in
    :class:`FeatureFlagRole`.
    """

    __tablename__ = "feature_flags"
    __table_args__ = {"comment": "Named feature flags keyed by a string id"}  # noqa: RUF012

    id: Mapped[str] = mapped_column(String(_FEATURE_FLAG_ID_LENGTH), primary_key=True)
    enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    description: Mapped[str | None] = mapped_column(
        String(2048),
        default=None,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    role_overrides: Mapped[list[FeatureFlagRole]] = relationship(
        init=False,
        back_populates="feature_flag",
        cascade="all, delete-orphan",
    )


class FeatureFlagRole(Base):
    """A per-role override of a :class:`FeatureFlag`.

    The presence of a row makes the flag considered *enabled* for any user
    holding the linked :class:`Role`, regardless of the flag's global
    ``enabled`` value. Immutable (no update) — delete and re-create to change,
    mirroring ``user_roles``. Unique on ``(feature_flag_id, role_id)``.
    """

    __tablename__ = "feature_flag_roles"
    __table_args__ = (
        UniqueConstraint(
            "feature_flag_id", "role_id", name="uq_feature_flag_roles_flag_id_role_id"
        ),
        {"comment": "Per-role overrides of feature flags"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    feature_flag_id: Mapped[str] = mapped_column(
        ForeignKey("feature_flags.id", ondelete="CASCADE"),
        index=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )

    feature_flag: Mapped[FeatureFlag] = relationship(init=False, back_populates="role_overrides")


__all__ = [
    "FeatureFlag",
    "FeatureFlagRole",
]
