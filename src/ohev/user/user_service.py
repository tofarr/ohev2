"""Service layer for the user feature.

Services contain business logic; repositories contain data access. This module
exposes a thin `UserService` over SQLAlchemy async sessions per AGENTS.md §4.
Every data-access method accepts a ``perm_filter`` (the effective search filter
from the centralized permission checker) that scopes the SQL to rows the
principal is allowed to see/modify; :meth:`create` validates the incoming item
against it in memory (AGENTS.md §9 — authorization enforced in services, not
just routers).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.user.user_models import User
from ohev.user.user_schemas import UserCreate, UserSearchFilter, UserUpdate
from ohev.util.search_filter import SearchFilter


class UserNotFoundError(Exception):
    """Raised when a user id does not exist."""


class UserEmailConflictError(Exception):
    """Raised when a create/update collides with an existing email."""


class UserPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class UserService:
    """CRUD operations over users.

    The service is constructed per request with the request-scoped session; it
    holds no mutable state of its own.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        payload: UserCreate,
        perm_filter: SearchFilter[User],
    ) -> User:
        """Create a user. Raises UserEmailConflictError on duplicate email.

        Raises :class:`UserPermissionScopeError` if the prospective user does
        not satisfy *perm_filter* (the principal's create scope).
        """
        user = User(email=payload.email)
        if not perm_filter.matches(user):
            raise UserPermissionScopeError(str(payload.email))
        self._session.add(user)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise UserEmailConflictError(payload.email) from exc
        # Refresh so server-side defaults (id, created_at, updated_at) are loaded
        # before the router commits and expires attributes.
        await self._session.refresh(user)
        return user

    async def get(
        self,
        user_id: uuid.UUID,
        perm_filter: SearchFilter[User],
    ) -> User:
        """Retrieve a user by id, scoped by *perm_filter*.

        Raises :class:`UserNotFoundError` if the user is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = perm_filter.filter_sql(select(User).where(User.id == user_id))
        result = await self._session.execute(stmt)
        user = result.scalar_one_or_none()
        if user is None:
            raise UserNotFoundError(str(user_id))
        return user

    async def search_users(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: UserSearchFilter | None = None,
        perm_filter: SearchFilter[User],
    ) -> tuple[list[User], uuid.UUID | None]:
        """Search users ordered by id, keyed-pagination via cursor.

        The permission filter (*perm_filter*) scopes the SQL to rows the
        principal may see; the optional *search_filter* (from query params) is
        ANDed on top. Returns (users, next_cursor). next_cursor is None when
        exhausted.
        """
        stmt = perm_filter.filter_sql(select(User).order_by(User.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(User.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        users = list(result.scalars().all())
        next_cursor = users[-1].id if len(users) == limit else None
        return users, next_cursor

    async def update(
        self,
        user_id: uuid.UUID,
        payload: UserUpdate,
        perm_filter: SearchFilter[User],
    ) -> User:
        """Partially update a user. Raises on missing/scoped-out user or email conflict."""
        user = await self.get(user_id, perm_filter)
        if payload.email is not None:
            user.email = payload.email
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise UserEmailConflictError(payload.email) from exc
        # Refresh so server-side onupdate (updated_at) is loaded before the
        # router commits and expires attributes.
        await self._session.refresh(user)
        return user

    async def delete(
        self,
        user_id: uuid.UUID,
        perm_filter: SearchFilter[User],
    ) -> None:
        """Delete a user. Raises UserNotFoundError if missing or out of scope."""
        user = await self.get(user_id, perm_filter)
        await self._session.delete(user)
        await self._session.flush()

    async def count(self, perm_filter: SearchFilter[User] | None = None) -> int:
        """Total user count, optionally scoped by *perm_filter* (used by tests/fixtures)."""
        stmt = select(func.count()).select_from(User)
        if perm_filter is not None:
            stmt = perm_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


# Re-export for type-checking convenience in callers that import from the
# service namespace.
__all__ = [
    "User",
    "UserEmailConflictError",
    "UserNotFoundError",
    "UserPermissionScopeError",
    "UserService",
]
