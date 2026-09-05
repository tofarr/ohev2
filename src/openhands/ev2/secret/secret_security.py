"""Permission policy and search filter for the secret resource.

Secrets use a custom permission policy, :class:`SecretAccess`, that differs
from the simple :class:`Permitted` / :class:`Denied` / :class:`ReadOnly`
policies: read, update, and delete are gated **per-secret** by the
``role_secret_permissions`` and ``user_secret_permissions`` link tables. A
principal may perform one of those actions on a secret only when they have a
direct :class:`UserSecretPermission` row or one of their roles has a
:class:`RoleSecretPermission` row for that secret with the matching flag
(``read_enabled`` / ``update_enabled`` / ``delete_enabled``) set. ``CREATE`` is
gated by the policy alone — a role carrying :class:`SecretAccess` (or
:class:`Permitted`) may create any secret; there is no per-secret grant because
no secret id exists until it is created.

Reduction to a :class:`SearchFilter` (AGENTS.md §11):

* ``CREATE`` → :class:`AllSearchFilter` (any principal whose role carries the
  policy may create secrets; the create payload is validated in-memory
  against this filter, which matches everything).
* ``READ`` / ``SEARCH`` → :class:`SecretAccessFilter` keyed on
  ``read_enabled``.
* ``UPDATE`` → :class:`SecretAccessFilter` keyed on ``update_enabled``.
* ``DELETE`` → :class:`SecretAccessFilter` keyed on ``delete_enabled``.

:class:`SecretAccessFilter` admits a secret iff its id appears in
``user_secret_permissions`` for the principal or in ``role_secret_permissions``
for one of the principal's roles (joined via ``user_roles``) with the keyed flag
enabled. The decision lives in SQL so it scales with the grant set; the
in-memory ``matches`` is permissive (returns ``True``) because the grant data
lives in the DB and is never materialized on a single item —
the only in-memory check the services perform is for ``CREATE`` (which uses
:class:`AllSearchFilter`), so :meth:`SecretAccessFilter.matches` is never the
authoritative check for a read/update/delete.

A role with ``secret_permission = Permitted()`` bypasses the per-secret grants
entirely (its :class:`AllSearchFilter` ORs into "match everything"), so an
admin role sees every secret. This mirrors how ``Permitted`` works for every
other governed entity.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.role.role_models import UserRole
from openhands.ev2.secret.secret_models import (
    RoleSecretPermission,
    Secret,
    UserSecretPermission,
)
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import (
    AllSearchFilter,
    NoneSearchFilter,
    SearchFilter,
    T,
)

# Maps an action to the :class:`RoleSecretPermission` flag column that admits it. CREATE
# has no entry (it is gated by the policy alone). SEARCH is treated as READ so
# listing a collection requires the read grant, consistent with single-item GET.
_ACTION_FLAG: dict[Action, str] = {
    Action.READ: "read_enabled",
    Action.SEARCH: "read_enabled",
    Action.UPDATE: "update_enabled",
    Action.DELETE: "delete_enabled",
}


class SecretAccessFilter(SearchFilter[T]):
    """Filter admitting secrets granted directly or through a role.

    Admits a :class:`Secret` iff the principal has a direct
    :class:`UserSecretPermission` row or one of their roles has a
    :class:`RoleSecretPermission` row for that secret with ``flag`` enabled.
    """

    user_id: uuid.UUID
    flag: str

    def matches(self, item: T) -> bool:
        # The grant data lives in the DB, not on the item, so an in-memory
        # decision is not possible. This filter is only ever the READ/UPDATE/
        # DELETE filter, whose scope is enforced in SQL via filter_sql; the
        # only in-memory check services perform is for CREATE, which uses
        # AllSearchFilter. Return True so any incidental in-memory use does
        # not spuriously deny; SQL remains authoritative.
        _ = item
        return True

    def sql_condition(self) -> ColumnElement[bool] | None:
        role_flag_col = getattr(RoleSecretPermission, self.flag)
        user_flag_col = getattr(UserSecretPermission, self.flag)
        role_granted = (
            select(RoleSecretPermission.secret_id)
            .join(UserRole, UserRole.role_id == RoleSecretPermission.role_id)
            .where(UserRole.user_id == self.user_id, role_flag_col.is_(True))
        )
        user_granted = select(UserSecretPermission.secret_id).where(
            UserSecretPermission.user_id == self.user_id, user_flag_col.is_(True)
        )
        return or_(Secret.id.in_(role_granted), Secret.id.in_(user_granted))


class SecretAccess(Permission):
    """Permission policy for the secret resource.

    ``CREATE`` is unrestricted (any principal whose role carries this policy
    may create secrets). ``READ``/``SEARCH``, ``UPDATE``, and ``DELETE`` are
    gated per-secret by direct user grants and role grants. A role with
    ``secret_permission = Permitted()`` bypasses the per-secret grants and gets
    full access (handled by :class:`Permitted`, not this policy).
    """

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        if action is Action.CREATE:
            return AllSearchFilter[Any]()
        if user_id is None:
            # Anonymous principals have no direct or role grants; deny read/update/delete.
            return NoneSearchFilter[Any]()
        flag = _ACTION_FLAG.get(action)
        if flag is None:
            return NoneSearchFilter[Any]()
        return SecretAccessFilter[Any](user_id=user_id, flag=flag)
