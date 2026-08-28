"""Service layer for the role-user assignment feature.

CRUD for the ``role_users`` link table (many-to-many between :class:`Role` and
:class:`User`). Assignments are immutable; there is no update — delete and
re-create to change (mirroring the CORS allow-list). The service does not take
a ``perm_filter`` because the link table is not a policy resource type;
authorization is governed by the ``role`` (and ``user``) resource policies via
the router's permission dependency (AGENTS.md §9 — authorization enforced in
services, but the link table has no resource policy of its own).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_user_schemas import RoleUserSearchFilter
from openhands.ev2.security.security_models import RoleUser


class RoleUserNotFoundError(Exception):
    """Raised when a role-user assignment id does not exist."""


class RoleUserConflictError(Exception):
    """Raised when an assignment already exists for the (role_id, user_id) pair."""


class RoleUserOrphanError(Exception):
    """Raised when the referenced role or user does not exist."""


class RoleUserService:
    """CRUD operations over role-user assignments."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, role_id: uuid.UUID, user_id: uuid.UUID) -> RoleUser:
        """Assign a role to a user. Raises RoleUserConflictError on duplicate,
        RoleUserOrphanError if the role or user does not exist."""
        link = RoleUser(role_id=role_id, user_id=user_id)
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, user_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, role_user_id: uuid.UUID) -> RoleUser:
        """Retrieve an assignment by id. Raises RoleUserNotFoundError if missing."""
        link = await self._session.get(RoleUser, role_user_id)
        if link is None:
            raise RoleUserNotFoundError(str(role_user_id))
        return link

    async def search_role_users(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: RoleUserSearchFilter | None = None,
    ) -> tuple[list[RoleUser], uuid.UUID | None]:
        """Search assignments ordered by id, keyed-pagination via cursor.

        Returns (assignments, next_cursor). next_cursor is None when exhausted.
        """
        stmt = select(RoleUser).order_by(RoleUser.id)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(RoleUser.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        links = list(result.scalars().all())
        next_cursor = links[-1].id if len(links) == limit else None
        return links, next_cursor

    async def count(
        self,
        search_filter: RoleUserSearchFilter | None = None,
    ) -> int:
        """Total assignment count, optionally narrowed by *search_filter*."""
        stmt = select(func.count()).select_from(RoleUser)
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def delete(self, role_user_id: uuid.UUID) -> None:
        """Delete an assignment. Raises RoleUserNotFoundError if missing."""
        link = await self.get(role_user_id)
        await self._session.delete(link)
        await self._session.flush()


def _classify_integrity_error(
    exc: IntegrityError,
    role_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Exception:
    """Map an IntegrityError to a duplicate vs orphan failure.

    A violation of the ``uq_role_users_role_id_user_id`` unique constraint means
    the assignment already exists (``RoleUserConflictError``); a foreign-key
    violation means the referenced role or user is missing
    (``RoleUserOrphanError``). asyncpg surfaces the constraint name in the
    error message; distinguish by it.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if "uq_role_users_role_id_user_id" in message or (
        "unique constraint" in message and "role_users" in message
    ):
        return RoleUserConflictError(f"{role_id}/{user_id}")
    if "foreign key" in message or "fk_" in message:
        if "user_id" in message and "role_id" not in message:
            return RoleUserOrphanError(f"user {user_id} does not exist")
        return RoleUserOrphanError(f"role {role_id} does not exist")
    # Default to conflict for any unrecognized integrity error on this table.
    return RoleUserConflictError(f"{role_id}/{user_id}")


__all__ = [
    "RoleUser",
    "RoleUserConflictError",
    "RoleUserNotFoundError",
    "RoleUserOrphanError",
    "RoleUserService",
]
