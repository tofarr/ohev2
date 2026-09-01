"""Service layer for the user-role assignment feature.

CRUD for the ``user_roles`` link table (many-to-many between :class:`Role` and
:class:`User`). Assignments are immutable; there is no update — delete and
re-create to change (mirroring the CORS allow-list). The link table is a
governed resource of its own (``user_role_permission`` on :class:`Role`):
the service holds the effective ``perm_filter`` and scopes every read/write
through it (AGENTS.md §9 — authorization enforced in services, not just
routers). Managing membership is deliberately *not* implied by
``role_permission`` update — editing a role's metadata and deciding who holds
it are separate grants.
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
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class UserRoleNotFoundError(Exception):
    """Raised when a user-role assignment id does not exist."""


class UserRoleConflictError(Exception):
    """Raised when an assignment already exists for the (role_id, user_id) pair."""


class UserRoleOrphanError(Exception):
    """Raised when the referenced role or user does not exist."""


class UserRolePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class UserRoleService:
    """CRUD operations over user-role assignments.

    Constructed per request with the request-scoped session and the principal's
    effective ``perm_filter`` (reduced from ``user_role_permission``); it holds
    no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[UserRole] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, role_id: uuid.UUID, user_id: uuid.UUID) -> UserRole:
        """Assign a role to a user. Raises UserRoleConflictError on duplicate,
        UserRoleOrphanError if the role or user does not exist, and
        UserRolePermissionScopeError if the assignment falls outside the
        principal's create scope."""
        link = UserRole(role_id=role_id, user_id=user_id)
        if not self._perm_filter.matches(link):
            raise UserRolePermissionScopeError(f"{role_id}/{user_id}")
        self._session.add(link)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, role_id, user_id) from exc
        await self._session.refresh(link)
        return link

    async def get(self, user_role_id: uuid.UUID) -> UserRole:
        """Retrieve an assignment by id, scoped by ``perm_filter``.

        Raises :class:`UserRoleNotFoundError` if the assignment is missing or
        out of the principal's scope (so callers return 404 without leaking
        existence).
        """
        stmt = self._perm_filter.filter_sql(select(UserRole).where(UserRole.id == user_role_id))
        result = await self._session.execute(stmt)
        link = result.scalar_one_or_none()
        if link is None:
            raise UserRoleNotFoundError(str(user_role_id))
        return link

    async def get_many(
        self,
        user_role_ids: list[uuid.UUID],
    ) -> list[UserRole | None]:
        """Retrieve assignments by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *user_role_ids*: the i-th entry
        is the :class:`UserRole` for ``user_role_ids[i]`` or ``None`` when
        missing or out of scope. Duplicate ids are preserved. An empty
        *user_role_ids* yields an empty list without hitting the DB.
        """
        if not user_role_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(UserRole).where(UserRole.id.in_(user_role_ids)))
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

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (assignments, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(UserRole).order_by(UserRole.id))
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
        """Total assignment count, scoped by ``perm_filter`` and the optional
        *search_filter*."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(UserRole))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def delete(self, user_role_id: uuid.UUID) -> None:
        """Delete an assignment. Raises UserRoleNotFoundError if missing or out
        of the principal's scope."""
        link = await self.get(user_role_id)
        await self._session.delete(link)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[UserRoleBatchOp],
        perm_filters: dict[Action, SearchFilter[UserRole] | None],
    ) -> list[UserRole | None]:
        """Apply a mix of create/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic: a failure
        of any operation rolls back the entire batch). Returns results aligned
        with *operations*: the created :class:`UserRole` for create ops,
        ``None`` for delete ops.
        """
        results: list[UserRole | None] = []
        for op in operations:
            if isinstance(op, UserRoleBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                link = await UserRoleService(self._session, filt).create(
                    op.data.role_id, op.data.user_id
                )
                results.append(link)
            elif isinstance(op, UserRoleBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await UserRoleService(self._session, filt).delete(op.id)
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
    "BatchPermissionDeniedError",
    "UserRole",
    "UserRoleConflictError",
    "UserRoleNotFoundError",
    "UserRoleOrphanError",
    "UserRolePermissionScopeError",
    "UserRoleService",
]
