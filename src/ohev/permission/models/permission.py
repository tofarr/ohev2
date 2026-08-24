"""ORM model for the permission feature.

A Permission is an immutable grant record: a *principal* (user) is granted an
*action* over a *resource type*, optionally restricted to a subset of
*attributes*. The shape is intentionally minimal and extensible:

  - action ∈ {create, read, update, delete, list, use, *}
  - type   ∈ {user, permission, …}  (extensible enum)
  - attributes = ["email", "name"] | None  (None ⇒ all attributes)

Permissions are immutable: there is no update operation. To change a grant,
delete and re-create. `action = "*"` is a wildcard matching any action. The
string grammar that round-trips a Permission to/from a compact string lives in
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

    `ALL` (`*`) is a wildcard matching any action. CRUD-L verbs cover the
    standard REST operations; `USE` covers non-CRUD resource-scoped actions
    (e.g. using an access token).
    """

    ALL = "*"
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    USE = "use"


class ResourceType(enum.StrEnum):
    """Resource types a permission may scope. Extensible as new entities land."""

    USER = "user"
    PERMISSION = "permission"


class Permission(Base):
    """A single immutable authorization grant.

    `(user_id, action, type, attributes)` identifies a grant. There is no
    `updated_at` and no update operation — permissions are delete-and-recreate.
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
    type: Mapped[ResourceType] = mapped_column(
        Enum(
            ResourceType,
            name="permission_resource_type",
            values_callable=lambda x: [e.value for e in x],
        ),
        index=True,
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

    user: Mapped[User] = relationship(init=False, lazy="selectin")

    def matches_action(self, requested: str) -> bool:
        """Whether this permission's action covers `requested`.

        Wildcard `*` covers everything; otherwise the action value must match.
        """
        if self.action is Action.ALL:
            return True
        return self.action.value == requested

    def matches_attributes(self, requested: list[str]) -> bool:
        """Whether this permission covers the requested attributes.

        `attributes is None` means all attributes are covered. Otherwise every
        requested attribute must be present in the allowed set.
        """
        if self.attributes is None:
            return True
        allowed = set(self.attributes)
        return all(a in allowed for a in requested)
