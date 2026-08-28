"""Models for the security module.

The security module is the successor to the legacy ``permission`` package. Its
central abstraction is :class:`Permission`, a discriminated-union (SDK
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

The :class:`Role` and :class:`UserRole` ORM models live in
``openhands.ev2.role.role_models``; this module only defines the policy types
(:class:`Permission` and subclasses) and the :class:`PermissionType` JSONB
column type used by those models.
"""

from __future__ import annotations

import enum
import uuid
from abc import ABC, abstractmethod
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from openhands.ev2.util.search_filter import (
    AllSearchFilter,
    NoneSearchFilter,
    SearchFilter,
)


class Action(enum.StrEnum):
    """Actions a permission policy may be evaluated against.

    CRUD verbs cover the standard REST operations; ``SEARCH`` covers collection
    retrieval, and ``USE`` covers non-CRUD resource-scoped actions (e.g. using
    an access token). There is no ``ALL`` wildcard — a policy decides for
    itself which actions it covers, so a wildcard action is redundant.
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    SEARCH = "search"
    USE = "use"


class Permission(DiscriminatedUnionMixin, ABC):
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


class Permitted(Permission):
    """Policy that always grants full, unrestricted access."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        return AllSearchFilter[Any]()


class Denied(Permission):
    """Policy that always denies access (matches no rows)."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        return NoneSearchFilter[Any]()


class ReadOnly(Permission):
    """Policy that grants read/search and denies all other actions."""

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        if action in (Action.READ, Action.SEARCH):
            return AllSearchFilter[Any]()
        return NoneSearchFilter[Any]()


class PermissionType(TypeDecorator[Permission | None]):
    """SQLAlchemy column type that persists a :class:`Permission` as JSONB.

    Stores the policy as a JSONB column on read/write, transparently
    serializing via ``model_dump`` and deserializing via the discriminated-union
    ``Permission.model_validate`` so the round-trip restores the concrete
    subclass. ``None`` is preserved as SQL ``NULL``.
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: Permission | dict[str, Any] | None,
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
    ) -> Permission | None:
        if value is None:
            return None
        return Permission.model_validate(value)
