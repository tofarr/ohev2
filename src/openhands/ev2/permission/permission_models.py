"""ORM model for the permission feature.

A Permission is an immutable grant record: a *principal* (user) is granted an
*action* over a *resource type*, optionally restricted to a subset of
*attributes* and optionally scoped by a *search filter*. The shape is
intentionally minimal and extensible:

  - action ∈ {create, read, update, delete, search, use, all}
  - type   ∈ {user, permission, …}  (extensible enum; column: resource_type)
  - attributes = ["email", "name"] | None  (None ⇒ all attributes)
  - search_filter = {"kind": "UserSearchFilter", ...} | None
    (None ⇒ unrestricted — the whole resource table is in scope)

``user_id`` is nullable: a ``None`` principal represents a permission that
applies even when no user is logged in (anonymous access). Permissions are
immutable: there is no update operation. To change a grant, delete and
re-create. The string grammar that round-trips a Permission to/from a compact
string lives in `permission/services/permission_grammar.py`.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.user.user_models import User


class Action(enum.StrEnum):
    """Actions a permission may grant.

    `ALL` (`all`) is a wildcard matching any action. CRUD verbs cover the
    standard REST operations; `SEARCH` covers collection retrieval, and `USE`
    covers non-CRUD resource-scoped actions (e.g. using an access token).
    """

    ALL = "all"
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    SEARCH = "search"
    USE = "use"


class ResourceType(enum.StrEnum):
    """Resource types a permission may scope. Extensible as new entities land."""

    USER = "user"
    PERMISSION = "permission"
    API_KEY = "api_key"


class Permission(Base):
    """A single immutable authorization grant.

    ``(user_id, action, resource_type, attributes, search_filter)`` identifies
    a grant. ``user_id`` may be ``None`` for permissions that apply to
    anonymous (not-logged-in) principals. There is no ``updated_at`` and no
    update operation — permissions are delete-and-recreate.
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
    # Nullable: a NULL user_id represents a permission that applies even when
    # no user is logged in (anonymous access).
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
        default=None,
    )
    action: Mapped[Action] = mapped_column(
        Enum(Action, name="permission_action", values_callable=lambda x: [e.value for e in x]),
        default=Action.READ,
    )
    resource_type: Mapped[ResourceType] = mapped_column(
        "resource_type",
        Enum(
            ResourceType,
            name="permission_resource_type",
            values_callable=lambda x: [e.value for e in x],
        ),
        index=True,
        default=ResourceType.USER,
    )
    attributes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        default=None,
        comment="Optional subset of attributes; null means all attributes.",
    )
    # Serialized SearchFilter (discriminated-union dict with a `kind` key).
    # NULL means "no restriction" — the entire resource table is in scope.
    search_filter: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        default=None,
        comment="Serialized search filter scoping the grant; null = unrestricted.",
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )

    user: Mapped[User | None] = relationship(init=False, lazy="selectin")

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
