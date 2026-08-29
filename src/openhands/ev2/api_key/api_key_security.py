"""Permission policy and search filter for the api_key resource.

API keys use a custom permission policy, :class:`ApiKeyAccess`, that scopes
every action to the principal's own keys: a principal may create, read, update,
delete, and search only API keys whose ``user_id`` equals their own. This is
the policy set on non-admin roles (e.g. the seeded ``user`` role) so a regular
user can manage their own API keys without an admin grant.

Reduction to a :class:`SearchFilter` (AGENTS.md §11):

* any action, with a known ``user_id`` → :class:`ApiKeyAccessFilter` keyed on
  ``ApiKey.user_id == user_id``.
* any action, anonymous (``user_id is None``) → :class:`NoneSearchFilter`
  (anonymous principals have no keys to manage).

A role with ``api_key_permission = Permitted()`` bypasses the self-scope
entirely (its :class:`AllSearchFilter` ORs into "match everything"), so an
admin role sees every key. This mirrors how ``Permitted`` works for every other
governed entity.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import (
    NoneSearchFilter,
    SearchFilter,
    T,
)


class ApiKeyAccessFilter(SearchFilter[T]):
    """Filter admitting API keys whose ``user_id`` equals the principal's.

    Admits an :class:`ApiKey` iff ``ApiKey.user_id == user_id``. Expressed both
    in-memory (for create-scope validation against a prospective row) and in SQL
    (for search/get/update/delete scoping).
    """

    user_id: uuid.UUID

    def matches(self, item: T) -> bool:
        return getattr(item, "user_id", None) == self.user_id

    def sql_condition(self) -> ColumnElement[bool] | None:
        return ApiKey.user_id == self.user_id


class ApiKeyAccess(Permission):
    """Permission policy scoping API-key management to the principal's own keys.

    Every action (CREATE/READ/UPDATE/DELETE/SEARCH) is gated by
    ``ApiKey.user_id == user_id``: a principal may only manage keys they own. A
    role with ``api_key_permission = Permitted()`` bypasses this and gets full
    access (handled by :class:`Permitted`, not this policy).
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        _ = action  # every action is scoped identically to the principal's own keys
        if user_id is None:
            return NoneSearchFilter[Any]()
        return ApiKeyAccessFilter[Any](user_id=user_id)
