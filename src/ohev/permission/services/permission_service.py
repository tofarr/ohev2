"""Service layer for the permission feature.

CRUD operations plus a pure `PermissionEvaluator` that answers authorization
questions against an in-memory permission set (the set typically loaded for a
principal at request time, or decoded from a JWT). The evaluator has no I/O so
it is unit-testable without a database (AGENTS.md §4, §5).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.permission.models.permission import (
    Action,
    Permission,
    SelectorKind,
)
from ohev.permission.schemas import PermissionCreate, PermissionUpdate


class PermissionNotFoundError(Exception):
    """Raised when a permission id does not exist."""


class PermissionConflictError(Exception):
    """Raised when a create collides with an existing permission row."""


class PermissionService:
    """CRUD operations over permissions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, payload: PermissionCreate) -> Permission:
        permission = Permission(
            user_id=payload.user_id,
            action=payload.action,
            custom_action=payload.custom_action,
            resource_type=payload.resource_type,
            selector_kind=payload.selector_kind,
            selector_value=payload.selector_value,
            attributes=payload.attributes,
        )
        self._session.add(permission)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise PermissionConflictError(str(payload)) from exc
        # Refresh so server-side defaults (id, created_at, updated_at) are loaded
        # before the router commits and expires attributes.
        await self._session.refresh(permission)
        return permission

    async def get(self, permission_id: uuid.UUID) -> Permission:
        permission = await self._session.get(Permission, permission_id)
        if permission is None:
            raise PermissionNotFoundError(str(permission_id))
        return permission

    async def list_permissions(
        self,
        *,
        user_id: uuid.UUID | None = None,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[Permission], uuid.UUID | None]:
        """List permissions optionally filtered by user, keyed by id."""
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

    async def update(self, permission_id: uuid.UUID, payload: PermissionUpdate) -> Permission:
        permission = await self.get(permission_id)
        if payload.action is not None:
            permission.action = payload.action
        if payload.custom_action is not None:
            permission.custom_action = payload.custom_action
        if payload.resource_type is not None:
            permission.resource_type = payload.resource_type
        if payload.selector_kind is not None:
            permission.selector_kind = payload.selector_kind
        if payload.selector_value is not None:
            permission.selector_value = payload.selector_value
        if payload.attributes is not None:
            permission.attributes = payload.attributes
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise PermissionConflictError(str(payload)) from exc
        # Refresh so server-side onupdate (updated_at) is loaded before the
        # router commits and expires attributes.
        await self._session.refresh(permission)
        return permission

    async def delete(self, permission_id: uuid.UUID) -> None:
        permission = await self.get(permission_id)
        await self._session.delete(permission)
        await self._session.flush()

    async def list_for_user(self, user_id: uuid.UUID) -> list[Permission]:
        """Load all permissions for a user (for evaluation)."""
        stmt = select(Permission).where(Permission.user_id == user_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count(self) -> int:
        stmt = select(func.count()).select_from(Permission)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


class PermissionEvaluator:
    """Pure authorization evaluator over an in-memory permission set.

    Stateless: constructed with the principal's permissions and asked
    `is_allowed`. No I/O — safe to unit test directly.
    """

    def __init__(self, permissions: list[Permission]) -> None:
        self._permissions = permissions

    def is_allowed(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        resource_tags: tuple[str, ...] = (),
        attributes: tuple[str, ...] = (),
    ) -> bool:
        """Whether the permission set grants `action` on the described resource.

        A permission matches iff: action covers the requested action, resource
        type equals, the selector covers the entity (ALL; BY_ID matches the
        id; BY_TAG matches one of the entity's tags), and the attributes subset
        covers the requested attributes.
        """
        requested_attrs = list(attributes)
        for perm in self._permissions:
            if perm.resource_type != resource_type:
                continue
            if not perm.matches_action(action):
                continue
            if not _selector_covers(perm, resource_id, resource_tags):
                continue
            if not perm.matches_attributes(requested_attrs):
                continue
            return True
        return False


def _selector_covers(
    perm: Permission,
    resource_id: str | None,
    resource_tags: tuple[str, ...],
) -> bool:
    if perm.selector_kind is SelectorKind.ALL:
        return True
    if perm.selector_kind is SelectorKind.BY_ID:
        return perm.selector_value is not None and perm.selector_value == resource_id
    if perm.selector_kind is SelectorKind.BY_TAG:
        return perm.selector_value is not None and perm.selector_value in resource_tags
    return False


# Re-export Action for convenience from the service namespace.
__all__ = [
    "Action",
    "PermissionConflictError",
    "PermissionEvaluator",
    "PermissionNotFoundError",
    "PermissionService",
]
