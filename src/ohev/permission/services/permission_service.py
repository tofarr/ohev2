"""Service layer for the permission feature.

CRUD operations (no update — permissions are immutable) plus a
`check_permission` method that resolves to a single SQL EXISTS query against
the per-user permission table. The config-level baseline (AppConfig.
base_permissions) is checked in-memory first; only if it does not already
grant the request is the DB consulted (AGENTS.md §4, §5).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.config import get_config
from ohev.permission.models.permission import (
    Action,
    Permission,
    ResourceType,
)
from ohev.permission.schemas import PermissionCreate
from ohev.permission.services.permission_grammar import parse_many


class PermissionNotFoundError(Exception):
    """Raised when a permission id does not exist."""


class PermissionConflictError(Exception):
    """Raised when a create collides with an existing permission row."""


class PermissionDeniedError(Exception):
    """Raised when a permission check fails."""

    def __init__(self, user_id: uuid.UUID, action: str, resource_type: str) -> None:
        self.user_id = user_id
        self.action = action
        self.resource_type = resource_type
        super().__init__(f"Permission denied: user={user_id} action={action} type={resource_type}")


_base_permissions_cache: list[Permission] | None = None


def _load_base_permissions() -> list[Permission]:
    """Parse and cache the config-level base permission grants.

    These apply to every authenticated user as a baseline. The result is cached
    at module level so the config is parsed at most once per process.
    `reset_base_permissions_cache()` clears it (used by tests after config
    changes).
    """
    global _base_permissions_cache
    if _base_permissions_cache is not None:
        return _base_permissions_cache
    parsed = parse_many(" ".join(get_config().base_permissions))
    base = [
        Permission(
            user_id=uuid.UUID(int=0),
            action=p.action,
            type=p.resource_type,
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
        if perm.type is not resource_type:
            continue
        if not perm.matches_action(action):
            continue
        if not perm.matches_attributes(list(attributes)):
            continue
        return True
    return False


class PermissionService:
    """CRUD operations plus permission checking over permissions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, payload: PermissionCreate) -> Permission:
        permission = Permission(
            user_id=payload.user_id,
            action=payload.action,
            type=payload.type,
            attributes=payload.attributes,
        )
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

    async def get(self, permission_id: uuid.UUID) -> Permission:
        permission = await self._session.get(Permission, permission_id)
        if permission is None:
            raise PermissionNotFoundError(str(permission_id))
        return permission

    async def search_permissions(
        self,
        *,
        user_id: uuid.UUID | None = None,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[Permission], uuid.UUID | None]:
        """Search permissions optionally filtered by user, keyed by id."""
        stmt = select(Permission).order_by(Permission.id)
        if user_id is not None:
            stmt = stmt.where(Permission.user_id == user_id)
        if cursor is not None:
            stmt = stmt.where(Permission.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        permissions = list(result.scalars().all())
        next_cursor = permissions[-1].id if len(permissions) == limit else None
        return permissions, next_cursor

    async def delete(self, permission_id: uuid.UUID) -> None:
        permission = await self.get(permission_id)
        await self._session.delete(permission)
        await self._session.flush()

    async def check_permission(
        self,
        user_id: uuid.UUID,
        action: Action,
        resource_type: ResourceType,
        attributes: tuple[str, ...] = (),
    ) -> bool:
        """Whether *user_id* is granted *action* on *resource_type*.

        Resolves to a single SQL EXISTS query against the permissions table.
        The config-level baseline is checked in-memory first; if it already
        grants the request, the DB is not consulted.
        """
        if _base_allows(action.value, resource_type, attributes):
            return True
        return await self._db_allows(user_id, action, resource_type, attributes)

    async def _db_allows(
        self,
        user_id: uuid.UUID,
        action: Action,
        resource_type: ResourceType,
        attributes: tuple[str, ...],
    ) -> bool:
        """Single SQL EXISTS query for the per-user permission check.

        Matches a row where: user_id matches, type matches, action is ALL or
        the exact action, and (attributes is NULL OR attributes ⊇ requested).
        """
        stmt = (
            select(literal(1))
            .select_from(Permission)
            .where(Permission.user_id == user_id)
            .where(Permission.type == resource_type)
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

    async def count(self) -> int:
        stmt = select(func.count()).select_from(Permission)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


# Re-export Action and ResourceType for convenience from the service namespace.
__all__ = [
    "Action",
    "PermissionConflictError",
    "PermissionDeniedError",
    "PermissionNotFoundError",
    "PermissionService",
    "ResourceType",
]
