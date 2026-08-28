"""Models for the security module.

The security module is the successor to the legacy ``permission`` package. Its
central abstraction is :class:`Permission2`, a discriminated-union (SDK
``DiscriminatedUnionMixin``) Pydantic model: a concrete permission policy that
knows how to reduce itself to a :class:`SearchFilter` for a given
``(user_id, action)`` pair. Storing the policy itself (rather than a serialized
filter) keeps the decision logic co-located with the data and lets the same
stored policy adapt as the requested action changes.

Initial implementations:

* :class:`Permitted`  — always grants full access (``AllSearchFilter``).
* :class:`Denied`     — always denies access (``NoneSearchFilter``).
* :class:`ReadOnly`   — grants read/search, denies everything else.

``Action`` is redefined here without the legacy ``ALL`` wildcard; the wildcard
was a property of the old per-row permission grant and is not meaningful for a
policy object that is already action-aware.
"""

from __future__ import annotations

import enum
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from sqlalchemy import ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from openhands.ev2.db import Base
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import (
    AllSearchFilter,
    NoneSearchFilter,
    SearchFilter,
)


class Action(enum.StrEnum):
    """Actions a permission2 policy may be evaluated against.

    CRUD verbs cover the standard REST operations; ``SEARCH`` covers collection
    retrieval, and ``USE`` covers non-CRUD resource-scoped actions (e.g. using
    an access token). Unlike the legacy :class:`openhands.ev2.permission.Action`
    there is no ``ALL`` wildcard — a policy decides for itself which actions it
    covers, so a wildcard action is redundant.
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    SEARCH = "search"
    USE = "use"


class Permission2(DiscriminatedUnionMixin, ABC):
    """Abstract base for a permission policy.

    Concrete subclasses participate in the SDK discriminated-union machinery
    (a ``kind`` computed field tags the concrete type) so a stored policy can be
    serialized to JSON and deserialized back to the right subclass. Subclasses
    implement :meth:`to_search_filter`, which reduces the policy to a
    :class:`SearchFilter` for the given ``(user_id, action)`` pair.
    """

    @abstractmethod
    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        """Reduce this policy to a search filter for ``(user_id, action)``.

        A returned :class:`NoneSearchFilter` means "deny" (no rows visible / no
        create allowed); an :class:`AllSearchFilter` means the whole resource
        table is in scope.
        """
        raise NotImplementedError


class Permitted(Permission2):
    """Policy that always grants full, unrestricted access."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        return AllSearchFilter[Any]()


class Denied(Permission2):
    """Policy that always denies access (matches no rows)."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        return NoneSearchFilter[Any]()


class ReadOnly(Permission2):
    """Policy that grants read/search and denies all other actions."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        if action in (Action.READ, Action.SEARCH):
            return AllSearchFilter[Any]()
        return NoneSearchFilter[Any]()


class Permission2Type(TypeDecorator[Permission2 | None]):
    """SQLAlchemy column type that persists a :class:`Permission2` as JSONB.

    Stores the policy as a JSONB column on read/write, transparently
    serializing via ``model_dump`` and deserializing via the discriminated-union
    ``Permission2.model_validate`` so the round-trip restores the concrete
    subclass. ``None`` is preserved as SQL ``NULL``.
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: Permission2 | dict[str, Any] | None,
        dialect: Any,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        return value.model_dump(mode="json")

    def process_result_value(
        self,
        value: dict[str, Any] | None,
        dialect: Any,
    ) -> Permission2 | None:
        if value is None:
            return None
        return Permission2.model_validate(value)


class Permission2MapType(TypeDecorator[dict[str, Permission2] | None]):
    """SQLAlchemy column type for a ``{resource_type: Permission2}`` JSONB map.

    Each value is serialized/deserialized via the discriminated-union
    ``Permission2.model_validate`` so the round-trip restores the concrete
    subclass. A missing key (or ``None`` map) means "no policy for this
    resource" (deny). Keys are resource-type names (e.g. ``"user"``,
    ``"api_key"``).
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: dict[str, Permission2] | None,
        dialect: Any,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        return {
            k: (v.model_dump(mode="json") if not isinstance(v, dict) else v)
            for k, v in value.items()
        }

    def process_result_value(
        self,
        value: dict[str, Any] | None,
        dialect: Any,
    ) -> dict[str, Permission2] | None:
        if value is None:
            return None
        return {k: Permission2.model_validate(v) for k, v in value.items()}


class Role(Base):
    """A named role bundling per-resource permission policies.

    The ``policies`` JSONB column maps a resource-type name (e.g. ``"user"``,
    ``"api_key"``) to a :class:`Permission2` policy that applies when a user
    assigned this role performs an action on that resource. A missing key means
    "deny" for that resource. This is the canonical, extensible store: new
    resource types are governed by adding a key rather than a column.

    The legacy ``role_permission`` and ``user_permission`` columns are retained
    for backward compatibility with existing data but are no longer consulted
    by the auth2 authorization dependency.
    """

    __tablename__ = "roles"
    __table_args__ = {"comment": "Named role bundling permission2 policies"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    policies: Mapped[dict[str, Permission2] | None] = mapped_column(
        Permission2MapType,
        default=None,
        comment="Map of resource-type name -> Permission2 policy; missing key = deny.",
    )
    role_permission: Mapped[Permission2 | None] = mapped_column(
        Permission2Type,
        default=None,
        comment="Permission2 policy for role/permission resources; null = deny.",
    )
    user_permission: Mapped[Permission2 | None] = mapped_column(
        Permission2Type,
        default=None,
        comment="Permission2 policy for user resources; null = deny.",
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


class RoleUser(Base):
    """Assignment of a :class:`Role` to a :class:`User`.

    Many-to-many link table. A user's effective permissions are the union of
    the policies on every role assigned to them.
    """

    __tablename__ = "role_users"
    __table_args__ = {"comment": "Role-to-user assignments"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )

    role: Mapped[Role] = relationship(init=False, lazy="selectin")
    user: Mapped[User] = relationship(init=False, lazy="selectin")
