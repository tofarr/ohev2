"""Search filters: declarative, reusable predicates over a resource type.

A `SearchFilter` is a discriminated-union (SDK `DiscriminatedUnionMixin`)
Pydantic model, generic over the entity type `T` it filters. It exposes two
views of the same predicate:

* `matches(item)` — an in-memory boolean check applied to a single entity
  instance. Used for permission-scoped row filtering and ad-hoc checks.
* `filter_sql(stmt)` — applies the predicate as SQLAlchemy WHERE clauses to a
  `Select` construct, so collection endpoints can push the filter into the DB
  query instead of materializing rows.

`BaseSearchFilter` is the convenience base for the common case where a filter
mirrors a resource's fields. A subclass declares optional fields named
`<attribute>__<op>` (e.g. `email__contains`, `created_at__gte`) and the base
reflects over its own Pydantic field declarations to build `matches` and
`filter_sql` automatically.

Supported operators (the suffix after the final `__`):

=========== =============================================================
suffix      semantics
=========== =============================================================
contains    substring / membership match (case-insensitive for `str`)
eq          equals
lt          strictly less than
lte         less than or equal
gt          strictly greater than
gte         greater than or equal
=========== =============================================================

Example::

    class UserSearchFilter(BaseSearchFilter[User]):
        email__contains: str | None = None
        created_at__gte: datetime | None = None

    f = UserSearchFilter(email__contains="alice")
    f.matches(user)                       # bool
    f.filter_sql(select(User))            # Select with WHERE applied

The same filter shapes are intended to be used as optional inclusions on
search endpoints and as the per-item scope of a permission grant.
"""

from __future__ import annotations

import operator
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any, Generic, TypeVar, cast

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from sqlalchemy.sql.selectable import Select

__all__ = ["BaseSearchFilter", "SearchFilter"]

T = TypeVar("T")

# Operators recognized on the `<attribute>__<op>` field-name convention.
# Each maps to (sql_builder, in_memory_predicate). The SQL builder receives
# the SQLAlchemy column and the filter value; the in-memory predicate receives
# the item's attribute value and the filter value.


def _naive(value: Any) -> Any:
    """Strip tzinfo from aware datetimes.

    ORM timestamp columns use `func.now()` (naive, server-side); comparing them
    against an aware datetime raises an asyncpg offset mismatch. Normalizing to
    naive keeps comparison operators safe for timestamp columns.
    """
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def _sql_contains(column: Any, value: Any) -> Any:
    # ilike is case-insensitive substring match; for non-string columns this
    # still works but is rarely meaningful. Stripping stray wildcards from
    # user input prevents LIKE-injection of `%`/`_`.
    safe = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.ilike(f"%{safe}%", escape="\\")


def _in_mem_contains(attr_value: Any, value: Any) -> bool:
    if attr_value is None:
        return False
    if isinstance(attr_value, str) and isinstance(value, str):
        return value.lower() in attr_value.lower()
    # Fall back to membership for sequence-typed attributes.
    try:
        return value in attr_value
    except TypeError:
        return False


_OPS: dict[str, tuple[Callable[[Any, Any], Any], Callable[[Any, Any], bool]]] = {
    "contains": (_sql_contains, _in_mem_contains),
    "eq": (lambda c, v: c == _naive(v), operator.eq),
    "lt": (lambda c, v: c < _naive(v), operator.lt),
    "lte": (lambda c, v: c <= _naive(v), operator.le),
    "gt": (lambda c, v: c > _naive(v), operator.gt),
    "gte": (lambda c, v: c >= _naive(v), operator.ge),
}

_SEPARATOR = "__"


# Generic[T] (not PEP 695 type params) is required so __class_getitem__ can
# capture the concrete entity type on the parameterized base class.
class SearchFilter(DiscriminatedUnionMixin, ABC, Generic[T]):  # noqa: UP046
    """Abstract base for a filter over entity type `T`.

    Concrete subclasses participate in the SDK discriminated-union machinery
    (a `kind` computed field tags the concrete filter type) so filter sets
    can be serialized and deserialized polymorphically.
    """

    # Resolved entity class for `BaseSearchFilter[T]` subclasses. Captured in
    # `__class_getitem__` (the parameterized base carries it) and inherited via
    # the MRO; never written from `__init_subclass__` so concrete subclasses
    # don't shadow the value with `None`.
    _entity_cls: type[Any] | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    def __class_getitem__(cls, item: Any) -> type[Any]:
        param = cast("type[Any]", super().__class_getitem__(item))
        arg = item[0] if isinstance(item, tuple) else item
        if isinstance(arg, type):
            param._entity_cls = arg
        return param

    @abstractmethod
    def matches(self, item: T) -> bool:
        """Whether *item* satisfies this filter."""
        raise NotImplementedError

    @abstractmethod
    def filter_sql(self, stmt: Select[tuple[T]]) -> Select[tuple[T]]:
        """Return *stmt* with this filter's WHERE clauses applied."""
        raise NotImplementedError


class BaseSearchFilter(SearchFilter[T]):
    """`SearchFilter` that derives its predicate from its own field names.

    A subclass declares optional fields named `<attr>__<op>` where `<op>` is
    one of: contains, eq, lt, lte, gt, gte. At call time the base reflects
    over the subclass's Pydantic fields, collects every non-`None` value, and
    applies the corresponding operator to the matching attribute of `T` — both
    in-memory (`matches`) and in SQL (`filter_sql`).

    The entity type `T` is resolved from the `Generic` parameterization (e.g.
    `BaseSearchFilter[User]`), so the SQLAlchemy column for an attribute is
    obtained via `getattr(entity_cls, attr)`.
    """

    def matches(self, item: T) -> bool:
        attr_value: Any
        for attr, op, value in self._active_clauses():
            _sql_builder, in_mem = _OPS[op]
            attr_value = getattr(item, attr, None)
            if not in_mem(attr_value, value):
                return False
        return True

    def filter_sql(self, stmt: Select[tuple[T]]) -> Select[tuple[T]]:
        entity = type(self)._entity_cls
        if not isinstance(entity, type):
            raise TypeError(
                f"{type(self).__name__} is not parameterized with a concrete entity "
                "type; subclass as BaseSearchFilter[YourEntity] to enable SQL filtering."
            )
        for attr, op, value in self._active_clauses():
            sql_builder, _ = _OPS[op]
            column = getattr(entity, attr, None)
            if column is None:
                raise AttributeError(
                    f"{entity.__name__!r} has no attribute {attr!r} "
                    f"required by filter field {attr!r}__{op}"
                )
            stmt = stmt.where(sql_builder(column, value))
        return stmt

    def _active_clauses(self) -> Iterator[tuple[str, str, Any]]:
        """Yield (attribute, operator, value) for every set filter field.

        Fields whose value is `None` are treated as "not set" and skipped,
        so a filter instance with no values matches everything.
        """
        for field_name in type(self).model_fields:
            head, sep, op = field_name.rpartition(_SEPARATOR)
            if not sep or head == "" or op not in _OPS:
                continue
            value = getattr(self, field_name)
            if value is None:
                continue
            yield head, op, value
