"""Service layer for the user-role assignment feature.

CRUD for the ``user_roles`` link table (many-to-many between :class:`Role` and
:class:`User`). Assignments are immutable; there is no update — delete and
re-create to change (mirroring the CORS allow-list). The service does not take
a ``perm_filter`` because the link table is governed by the ``user_role``
permission column on :class:`Role`; authorization is enforced via the router's
permission dependency on the ``role`` resource (AGENTS.md §9 — authorization
enforced in services, but the link table has no resource policy of its own).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import UserRole
from openhands.ev2.role.user_role_schemas import (
    UserRoleBatchCreate,
    UserRoleBatchDelete,
    UserRoleBatchOp,
    UserRoleSearchFilter,
)


class UserRoleNotFoundError(Exception):
    """Raised when a user-role assignment id does not exist."""


class UserRoleConflictError(Exception):
    """Raised when an assignment already exists for the (role_id, user_id) pair."""


class UserRoleOrphanError(Exception):
    """Raised when the referenced role or user does not exist."""


class UserRoleService:
    """CRUD operations over user-role assignments."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, role_id: uuid.UUID, user_id: uuid.UUID) -> UserRole:
        """Assign a role to a user. Raises UserRoleConflictError on duplicate,
        UserRoleOrphanError if the role or user does not exist."""
        link = UserRole(role_id=role_id, user_id=user_id)
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, user_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, user_role_id: uuid.UUID) -> UserRole:
        """Retrieve an assignment by id. Raises UserRoleNotFoundError if missing."""
        link = await self._session.get(UserRole, user_role_id)
        if link is None:
            raise UserRoleNotFoundError(str(user_role_id))
        return link

    async def get_many(
        self,
        user_role_ids: list[uuid.UUID],
    ) -> list[UserRole | None]:
        """Retrieve assignments by ids in a single query.

        Returns a list positionally aligned with *user_role_ids*: the i-th entry
        is the :class:`UserRole` for ``user_role_ids[i]`` or ``None`` when
        missing. Duplicate ids are preserved. An empty *user_role_ids* yields an
        empty list without hitting the DB.
        """
        if not user_role_ids:
            return []
        stmt = select(UserRole).where(UserRole.id.in_(user_role_ids))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, UserRole] = {link.id: link for link in result.scalars().all()}
        return [by_id.get(lid) for lid in user_role_ids]

    async def search_user_roles(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: UserRoleSearchFilter | None = None,
    ) -> tuple[list[UserRole], uuid.UUID | None]:
        """Search assignments ordered by id, keyed-pagination via cursor.

        Returns (assignments, next_cursor). next_cursor is None when exhausted.
        """
        stmt = select(UserRole).order_by(UserRole.id)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(UserRole.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(
        self,
        search_filter: UserRoleSearchFilter | None = None,
    ) -> int:
        """Total assignment count, optionally narrowed by *search_filter*."""
        stmt = select(func.count()).select_from(UserRole)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def delete(self, user_role_id: uuid.UUID) -> None:
        """Delete an assignment. Raises UserRoleNotFoundError if missing."""
        link = await self.get(user_role_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[UserRoleBatchOp],
    ) -> list[UserRole | None]:
        """Apply a mix of create/delete operations in one transaction.

        Authorization is enforced at the router (the principal must have
        ``UPDATE`` on the ``role`` resource to manage assignments, mirroring
        single-item create/delete). No commit is performed — the caller commits
        once after the whole batch succeeds (atomic: a failure of any operation
        rolls back the entire batch). Returns results aligned with *operations*:
        the created :class:`UserRole` for create ops, ``None`` for delete ops.
        """
        results: list[UserRole | None] = []
        for op in operations:
            if isinstance(op, UserRoleBatchCreate):
                link = await self.create(op.data.role_id, op.data.user_id)
                results.append(link)
            elif isinstance(op, UserRoleBatchDelete):
                await self.delete(op.id)
                results.append(None)
        return results


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of the ``uq_user_roles_role_id_user_id`` unique constraint means
    the assignment already exists (``UserRoleConflictError``); a foreign-key
    violation means the referenced role or user is missing
    (``UserRoleOrphanError``). asyncpg surfaces the constraint name in the
    error message; distinguish by it.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_user_roles_role_id_user_id" in message or (
        "unique constraint" in message and "user_roles" in message
    ):
        return UserRoleConflictError(f"{role_id}/{user_id}")
    if "foreign key" in message or "fk_" in message:
        if "user_id" in message and "role_id" not in message:
            return UserRoleOrphanError(f"user {user_id} does not exist")
        return UserRoleOrphanError(f"role {role_id} does not exist")
    # Default to conflict for any unrecognized integrity error on this table.
    return UserRoleConflictError(f"{role_id}/{user_id}")


__all__ = [
    "UserRole",
    "UserRoleConflictError",
    "UserRoleNotFoundError",
    "UserRoleOrphanError",
    "UserRoleService",
]
