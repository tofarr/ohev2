"""Service layer for the permission feature.

CRUD operations (no update — permissions are immutable) plus the centralized
permission checker :meth:`PermissionService.get_effective_filter`. The checker
loads every permission grant that applies to the current principal for a given
``(action, resource_type)`` — including the ``ALL`` wildcard action and
anonymous (``user_id IS NULL``) grants — and combines their search filters with
``Or`` into a single :class:`SearchFilter`. ``None`` is returned when no grant
applies, which callers interpret as "deny" (no rows visible / no create
allowed). The config-level baseline (``AppConfig.base_permissions``) is checked
in-memory first and contributes an unrestricted (``All``) scope when it grants
the request (AGENTS.md §4, §9, §10).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, literal, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.config import get_config
from ohev.permission.permission_grammar import parse_many
from ohev.permission.permission_models import (
    Action,
    Permission,
    ResourceType,
)
from ohev.permission.permission_schemas import PermissionCreate, PermissionSearchFilter
from ohev.util.search_filter import (
    ALL_SEARCH_FILTER,
    AllSearchFilter,
    OrSearchFilter,
    SearchFilter,
)


class PermissionNotFoundError(Exception):
    """Raised when a permission id does not exist."""


class PermissionConflictError(Exception):
    """Raised when a create collides with an existing permission row."""


class PermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class PermissionDeniedError(Exception):
    """Raised when a permission check fails."""

    def __init__(self, user_id: uuid.UUID | None, action: str, resource_type: str) -> None:
        self.user_id = user_id
        self.action = action
        self.resource_type = resource_type
        super().__init__(
            f"Permission denied: user={user_id} action={action} resource_type={resource_type}"
        )


_base_permissions_cache: list[Permission] | None = None


def _load_base_permissions() -> list[Permission]:
    """Parse and cache the config-level base permission grants.

    These apply to every request as a baseline (including anonymous ones). The
    result is cached at module level so the config is parsed at most once per
    process. `reset_base_permissions_cache()` clears it (used by tests after
    config changes).
    """
    global _base_permissions_cache
    if _base_permissions_cache is not None:
        return _base_permissions_cache
    parsed = parse_many(" ".join(get_config().base_permissions))
    base = [
        Permission(
            user_id=None,
            action=p.action,
            resource_type=p.resource_type,
            attributes=p.attributes,
        )
        for p in parsed
    ]
    _base_permissions_cache = base
    return base


def reset_base_permissions_cache() -> None:
    """Clear the cached base permissions (used by tests after config changes)."""
    global _base_permissions_cache
    _base_permissions_cache = None


def _base_allows(
    action: str,
    resource_type: ResourceType,
    attributes: tuple[str, ...],
) -> bool:
    """Whether the config baseline grants the request (no I/O)."""
    for perm in _load_base_permissions():
        if perm.resource_type is not resource_type:
            continue
        if not perm.matches_action(action):
            continue
        if not perm.matches_attributes(list(attributes)):
            continue
        return True
    return False


class PermissionService:
    """CRUD operations plus the centralized permission checker over permissions."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Any] = ALL_SEARCH_FILTER,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: PermissionCreate,
    ) -> Permission:
        """Create a permission.

        Raises :class:`PermissionScopeError` if the prospective permission does
        not satisfy the service's ``perm_filter`` (the principal's create scope
        on the permission resource).
        """
        permission = Permission(
            user_id=payload.user_id,
            action=payload.action,
            resource_type=payload.resource_type,
            attributes=payload.attributes,
            search_filter=payload.search_filter,
        )
        if not self._perm_filter.matches(permission):
            raise PermissionScopeError(str(payload))
        self._session.add(permission)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise PermissionConflictError(str(payload)) from exc
        # Refresh so server-side defaults (id, created_at) are loaded before
        # the router commits and expires attributes.
        await self._session.refresh(permission)
        return permission

    async def get(
        self,
        permission_id: uuid.UUID,
    ) -> Permission:
        """Retrieve a permission by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(Permission).where(Permission.id == permission_id)
        )
        result = await self._session.execute(stmt)
        permission: Permission | None = result.scalar_one_or_none()
        if permission is None:
            raise PermissionNotFoundError(str(permission_id))
        return permission

    async def search_permissions(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: PermissionSearchFilter | None = None,
    ) -> tuple[list[Permission], uuid.UUID | None]:
        """Search permissions, keyed by id.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        """
        stmt = self._perm_filter.filter_sql(select(Permission).order_by(Permission.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Permission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        permissions = list(result.scalars().all())
        next_cursor = permissions[-1].id if len(permissions) == limit else None
        return permissions, next_cursor

    async def delete(
        self,
        permission_id: uuid.UUID,
    ) -> None:
        permission = await self.get(permission_id)
        await self._session.delete(permission)
        await self._session.flush()

    async def check_permission(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        resource_type: ResourceType,
        attributes: tuple[str, ...] = (),
    ) -> bool:
        """Whether *user_id* is granted *action* on *resource_type*.

        Delegates to :meth:`get_effective_filter`: a returned filter means the
        action is allowed (scoped by the filter); ``None`` means denial.
        """
        return await self.get_effective_filter(user_id, action, resource_type) is not None

    async def get_effective_filter(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        resource_type: ResourceType,
    ) -> SearchFilter[Any] | None:
        """Build the effective search filter for *(action, resource_type)*.

        Loads every permission grant that applies to the current principal for
        ``(action, resource_type)`` — including the ``ALL`` wildcard action and
        anonymous (``user_id IS NULL``) grants — and combines their search
        filters with ``Or``. The config-level baseline contributes an
        unrestricted (``All``) scope when it grants the request.

        Returns ``None`` when no grant applies, which callers interpret as
        "deny" (no rows visible / no create allowed). A returned
        :class:`AllSearchFilter` means the whole resource table is in scope.
        """
        filters: list[SearchFilter[Any]] = []
        # Config baseline is an unrestricted (All) grant when it covers the
        # request; it does not carry a row-level scope.
        if _base_allows(action.value, resource_type, ()):
            filters.append(AllSearchFilter[Any]())
        filters.extend(
            self._deserialize_filter(p.search_filter, resource_type)
            for p in await self._load_permissions(user_id, action, resource_type)
        )
        if not filters:
            return None
        if len(filters) == 1:
            return filters[0]
        return OrSearchFilter(filters=filters)

    async def _load_permissions(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        resource_type: ResourceType,
    ) -> list[Permission]:
        """Load all DB grants matching the principal, action, and resource type.

        Matches rows where: user_id is the principal or NULL (anonymous),
        resource_type matches, and action is ALL or the exact action.
        """
        user_clause = (
            Permission.user_id.is_(None)
            if user_id is None
            else or_(Permission.user_id == user_id, Permission.user_id.is_(None))
        )
        stmt = (
            select(Permission)
            .where(user_clause)
            .where(Permission.resource_type == resource_type)
            .where((Permission.action == Action.ALL) | (Permission.action == action))
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    def _deserialize_filter(
        data: dict[str, Any] | None,
        resource_type: ResourceType,
    ) -> SearchFilter[Any]:
        """Deserialize a stored search-filter dict into a SearchFilter.

        A ``None`` (unrestricted) grant contributes an :class:`AllSearchFilter`.
        The discriminated-union ``kind`` in *data* resolves the concrete
        subclass; the resource's entity class is already captured on the
        parameterized filter class (e.g. ``UserSearchFilter._entity_cls``).
        """
        if data is None:
            return AllSearchFilter[Any]()
        return SearchFilter.model_validate(data)

    async def _db_allows(
        self,
        user_id: uuid.UUID | None,
        action: Action,
        resource_type: ResourceType,
        attributes: tuple[str, ...],
    ) -> bool:
        """Single SQL EXISTS query for the per-user permission check.

        Matches a row where: user_id is the principal or NULL, resource_type
        matches, action is ALL or the exact action, and (attributes is NULL OR
        attributes ⊇ requested).
        """
        user_clause = (
            Permission.user_id.is_(None)
            if user_id is None
            else or_(Permission.user_id == user_id, Permission.user_id.is_(None))
        )
        stmt = (
            select(literal(1))
            .select_from(Permission)
            .where(user_clause)
            .where(Permission.resource_type == resource_type)
            .where((Permission.action == Action.ALL) | (Permission.action == action))
        )
        if attributes:
            # PostgreSQL array containment operator: attributes @> requested
            stmt = stmt.where(
                (Permission.attributes.is_(None))
                | (Permission.attributes.op("@>")(list(attributes)))
            )
        result = await self._session.execute(stmt.limit(1))
        return result.scalar_one_or_none() is not None

    async def search_for_user(self, user_id: uuid.UUID) -> list[Permission]:
        """Load all permissions for a user (for evaluation/debugging)."""
        stmt = select(Permission).where(Permission.user_id == user_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count(
        self,
        search_filter: PermissionSearchFilter | None = None,
    ) -> int:
        """Total permission count, scoped by the service's ``perm_filter`` and
        the optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Permission))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


# Re-export Action and ResourceType for convenience from the service namespace.
__all__ = [
    "Action",
    "PermissionConflictError",
    "PermissionDeniedError",
    "PermissionNotFoundError",
    "PermissionScopeError",
    "PermissionService",
    "ResourceType",
]
