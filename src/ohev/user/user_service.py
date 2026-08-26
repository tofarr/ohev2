"""Service layer for the user feature.

Services contain business logic; repositories contain data access. This module
exposes a thin `UserService` over SQLAlchemy async sessions per AGENTS.md §4.
The service holds the effective ``perm_filter`` (the search filter from the
centralized permission checker) as a field, set at construction, that scopes
the SQL to rows the principal is allowed to see/modify; :meth:`create` validates
the incoming item against it in memory (AGENTS.md §9 — authorization enforced
in services, not just routers).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.user.user_models import User
from ohev.user.user_schemas import UserCreate, UserSearchFilter, UserUpdate
from ohev.util.search_filter import ALL_SEARCH_FILTER, SearchFilter


class UserNotFoundError(Exception):
    """Raised when a user id does not exist."""


class UserEmailConflictError(Exception):
    """Raised when a create/update collides with an existing email."""


class UserPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class UserService:
    """CRUD operations over users.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[User] = ALL_SEARCH_FILTER,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: UserCreate,
    ) -> User:
        """Create a user. Raises UserEmailConflictError on duplicate email.

        Raises :class:`UserPermissionScopeError` if the prospective user does
        not satisfy the service's ``perm_filter`` (the principal's create scope).
        """
        user = User(email=payload.email)
        if not self._perm_filter.matches(user):
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
    ) -> User:
        """Retrieve a user by id, scoped by ``perm_filter``.

        Raises :class:`UserNotFoundError` if the user is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(User).where(User.id == user_id))
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
    ) -> tuple[list[User], uuid.UUID | None]:
        """Search users ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (users, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(User).order_by(User.id))
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
    ) -> User:
        """Partially update a user. Raises on missing/scoped-out user or email conflict."""
        user = await self.get(user_id)
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
    ) -> None:
        """Delete a user. Raises UserNotFoundError if missing or out of scope."""
        user = await self.get(user_id)
        await self._session.delete(user)
        await self._session.flush()

    async def count(
        self,
        search_filter: UserSearchFilter | None = None,
    ) -> int:
        """Total user count, scoped by the service's ``perm_filter`` and the
        optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(User))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
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
