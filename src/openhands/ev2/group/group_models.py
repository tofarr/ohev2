"""ORM models for the group feature.

Two tables:

* :class:`Group` — a named collection of users. Carries an optional
  ``description`` and a ``creator_id`` referencing the :class:`User` that
  created it. Full CRUD (create/read/update/delete).
* :class:`GroupUser` — the link table ``group_users`` assigning a
  :class:`User` to a :class:`Group`. Immutable (no update) — delete and
  re-create to change a membership, mirroring ``user_roles``. Unique on
  ``(group_id, user_id)``.

The ``group_permission`` and ``group_user_permission`` columns on
:class:`Role` (and entries in ``ROLE_ENTITY_COLUMNS``) govern these resources;
see AGENTS.md §11. ``GroupUser`` is a governed link table of its own
(AGENTS.md §11.1): managing membership is deliberately *not* implied by
``group_permission`` update — editing a group's metadata and deciding who is a
member are separate grants.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.user.user_models import User


class Group(Base):
    """A named collection of users.

    ``creator_id`` is the :class:`User` that created the group, set from the
    authenticated principal at creation time (never accepted on the payload).
    """

    __tablename__ = "groups"
    __table_args__ = {"comment": "Named groups of users"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        String(2048),
        default=None,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )

    members: Mapped[list[GroupUser]] = relationship(
        init=False,
        back_populates="group",
        cascade="all, delete-orphan",
    )


class GroupUser(Base):
    """Assignment of a :class:`User` to a :class:`Group`.

    Many-to-many link table (``group_users``). Immutable (no update) — delete
    and re-create to change a membership, mirroring ``user_roles``. Unique on
    ``(group_id, user_id)``. ``creator_id`` is the principal that added the
    member.
    """

    __tablename__ = "group_users"
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_users_group_id_user_id"),
        {"comment": "Group-to-user memberships"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.clock_timestamp(),
    )

    group: Mapped[Group] = relationship(init=False, back_populates="members")
    user: Mapped[User] = relationship(init=False, lazy="selectin", foreign_keys=[user_id])
