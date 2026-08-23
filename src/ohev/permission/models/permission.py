"""ORM model for the permission feature.

A Permission is a policy record of the form: a *principal* (user) is granted an
*action* over a *resource* (type + selector) optionally restricted to a subset of
*attributes*. This single shape covers all the scoping cases discussed:

  - all entities of a type   -> selector_kind = ALL
  - subset by tag            -> selector_kind = BY_TAG
  - single entity            -> selector_kind = BY_ID
  - read/write/create/delete -> action in {create, read, write, delete}
  - non-CRUD action          -> action = custom verb (e.g. "use")
  - attribute subset         -> attributes = ["email", "name"]

`action = "*"` is a wildcard matching any action. The string grammar that
round-trips a Permission to/from a compact string lives in
`permission/services/permission_grammar.py`.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ohev.db import Base
from ohev.user.models.user import User


class Action(enum.StrEnum):
    """Actions a permission may grant.

    `ALL` (`*`) is a wildcard matching any action. CRUD verbs cover the standard
    REST operations; non-CRUD verbs (e.g. `use` for an access token) are stored
    as the literal string via the `CUSTOM` member plus `custom_action`.
    """

    ALL = "*"
    CREATE = "create"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    USE = "use"


class SelectorKind(enum.StrEnum):
    """How a permission scopes the set of entities of a resource type."""

    ALL = "all"
    BY_ID = "by_id"
    BY_TAG = "by_tag"


class Permission(Base):
    """A single authorization grant.

    `(user_id, action, resource_type, selector_kind, selector_value, attributes)`
    is unique — a principal gets at most one permission row per scoped resource.
    """

    __tablename__ = "permissions"
    # Standard SQLAlchemy table-args dict; MappedAsDataclass + ruff RUF012
    # flag it as a mutable class default, but it is the documented idiom.
    __table_args__ = {"comment": "ABAC permission grants"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    action: Mapped[Action] = mapped_column(
        Enum(Action, name="permission_action", values_callable=lambda x: [e.value for e in x]),
    )
    # Fields without defaults must precede defaulted ones in MappedAsDataclass.
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    custom_action: Mapped[str | None] = mapped_column(
        String(64),
        default=None,
        comment="Literal action verb when action is non-CRUD (e.g. 'use').",
    )
    selector_kind: Mapped[SelectorKind] = mapped_column(
        Enum(
            SelectorKind,
            name="permission_selector_kind",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=SelectorKind.ALL,
    )
    selector_value: Mapped[str | None] = mapped_column(
        String(255),
        default=None,
        comment="Entity id (BY_ID) or tag (BY_TAG); null for ALL.",
    )
    attributes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        default=None,
        comment="Optional subset of attributes; null means all attributes.",
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

    user: Mapped[User] = relationship(init=False, lazy="selectin")

    def matches_action(self, requested: str) -> bool:
        """Whether this permission's action covers `requested`.

        Wildcard `*` covers everything. CRUD actions match by value. A custom
        action matches only its literal verb.
        """
        if self.action is Action.ALL:
            return True
        if self.action.value == requested:
            return True
        return self.action is Action.USE and self.custom_action == requested

    def matches_attributes(self, requested: list[str]) -> bool:
        """Whether this permission covers the requested attributes.

        `attributes is None` means all attributes are covered. Otherwise every
        requested attribute must be present in the allowed set.
        """
        if self.attributes is None:
            return True
        allowed = set(self.attributes)
        return all(a in allowed for a in requested)
