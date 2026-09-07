"""Permission policies and search filters for sandbox resources.

The three public sandbox resources — :class:`SandboxTemplate`,
:class:`Sandbox`, and :class:`SandboxSnapshot` — use a custom permission
policy, :class:`SandboxAccess`, that mirrors :class:`SecretAccess`: read,
update, and delete are gated **per-resource** by the
``role_sandbox_template_permissions``, ``role_sandbox_permissions``, and
``role_sandbox_snapshot_permissions`` link tables respectively. A principal
may perform one of those actions on a resource only when one of their roles
has a grant row for that resource with the matching flag
(``read_enabled`` / ``update_enabled`` / ``delete_enabled``) set. ``CREATE``
is gated by the policy alone — a role carrying :class:`SandboxAccess` (or
:class:`Permitted`) may create any resource; there is no per-resource grant
because no resource id exists until it is created.

A role with ``<entity>_permission = Permitted()`` bypasses the per-resource
grants entirely (its :class:`AllSearchFilter` ORs into "match everything"),
so an admin role sees every resource. This mirrors how ``Permitted`` works
for every other governed entity.

Each resource type is parameterized by its grant link model, its resource
model, and the foreign-key column on the grant model that points at the
resource, so the three resources share one filter implementation.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, cast

from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement

from openhands.ev2.role.role_models import UserRole
from openhands.ev2.sandbox.sandbox_models import (
    RoleSandboxPermission,
    RoleSandboxSnapshotPermission,
    RoleSandboxTemplatePermission,
    Sandbox,
    SandboxSnapshot,
    SandboxTemplate,
)
from openhands.ev2.security.security_models import Action, Permission
from openhands.ev2.util.search_filter import (
    AllSearchFilter,
    NoneSearchFilter,
    SearchFilter,
    T,
)

# Maps an action to the grant flag column that admits it. CREATE has no entry
# (gated by the policy alone). SEARCH is treated as READ so listing a
# collection requires the read grant, consistent with single-item GET.
_ACTION_FLAG: dict[Action, str] = {
    Action.READ: "read_enabled",
    Action.SEARCH: "read_enabled",
    Action.UPDATE: "update_enabled",
    Action.DELETE: "delete_enabled",
}


class SandboxAccessFilter(SearchFilter[T]):
    """Filter admitting sandbox resources granted through a role.

    Admits a resource iff one of the principal's roles (joined via
    ``user_roles``) has a grant row for that resource with ``flag`` enabled.
    The grant model, resource model, and the grant model's foreign-key column
    pointing at the resource are bound at construction so the three sandbox
    resource types share one implementation.
    """

    user_id: uuid.UUID
    flag: str
    grant_model: type[Any]
    resource_model: type[Any]
    grant_resource_fk: str

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
        flag_col = cast("ColumnElement[bool]", getattr(self.grant_model, self.flag))
        resource_fk_col = cast(
            "ColumnElement[uuid.UUID]",
            getattr(self.grant_model, self.grant_resource_fk),
        )
        granted = (
            select(resource_fk_col)
            .join(UserRole, UserRole.role_id == self.grant_model.role_id)
            .where(UserRole.user_id == self.user_id, flag_col.is_(True))
        )
        return cast("ColumnElement[bool]", self.resource_model.id.in_(granted))


class SandboxAccess(Permission):
    """Permission policy for sandbox resources.

    ``CREATE`` is unrestricted (any principal whose role carries this policy
    may create the resource). ``READ``/``SEARCH``, ``UPDATE``, and ``DELETE``
    are gated per-resource by role grants. A role with
    ``<entity>_permission = Permitted()`` bypasses the per-resource grants and
    gets full access (handled by :class:`Permitted`, not this policy).

    The resource type is bound at construction so the three sandbox resources
    share one policy class.
    """

    grant_model: ClassVar[type[Any]]
    resource_model: ClassVar[type[Any]]
    grant_resource_fk: ClassVar[str]

    def to_search_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
    ) -> SearchFilter[Any]:
        if action is Action.CREATE:
            return AllSearchFilter[Any]()
        if user_id is None:
            # Anonymous principals have no role grants; deny read/update/delete.
            return NoneSearchFilter[Any]()
        flag = _ACTION_FLAG.get(action)
        if flag is None:
            return NoneSearchFilter[Any]()
        return SandboxAccessFilter[Any](
            user_id=user_id,
            flag=flag,
            grant_model=self.grant_model,
            resource_model=self.resource_model,
            grant_resource_fk=self.grant_resource_fk,
        )


class SandboxTemplateAccess(SandboxAccess):
    """SandboxAccess bound to the sandbox template resource."""

    grant_model: ClassVar[type[Any]] = RoleSandboxTemplatePermission
    resource_model: ClassVar[type[Any]] = SandboxTemplate
    grant_resource_fk: ClassVar[str] = "sandbox_template_id"


class SandboxResourceAccess(SandboxAccess):
    """SandboxAccess bound to the sandbox resource."""

    grant_model: ClassVar[type[Any]] = RoleSandboxPermission
    resource_model: ClassVar[type[Any]] = Sandbox
    grant_resource_fk: ClassVar[str] = "sandbox_id"


class SandboxSnapshotAccess(SandboxAccess):
    """SandboxAccess bound to the sandbox snapshot resource."""

    grant_model: ClassVar[type[Any]] = RoleSandboxSnapshotPermission
    resource_model: ClassVar[type[Any]] = SandboxSnapshot
    grant_resource_fk: ClassVar[str] = "sandbox_snapshot_id"


__all__ = [
    "SandboxAccess",
    "SandboxAccessFilter",
    "SandboxResourceAccess",
    "SandboxSnapshotAccess",
    "SandboxTemplateAccess",
]
