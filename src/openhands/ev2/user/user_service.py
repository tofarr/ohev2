"""Service layer for the user feature.

Services contain business logic; repositories contain data access. This module
exposes a thin `UserService` over SQLAlchemy async sessions per AGENTS.md §4.
The service holds the effective ``perm_filter`` (the search filter from the
centralized permission checker) as a field, set at construction, that scopes
the SQL to rows the principal is allowed to see/modify; :meth:`create` validates
the incoming item against it in memory (AGENTS.md §9 — authorization enforced
in services, not just routers). Passwords are hashed with bcrypt
(``util.password``) before persistence; plaintext never rests in the DB.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.user.user_models import User
from openhands.ev2.user.user_schemas import UserCreate, UserSearchFilter, UserUpdate
from openhands.ev2.util.password import hash_password, verify_password
from openhands.ev2.util.search_filter import ALL_SEARCH_FILTER, SearchFilter


class UserNotFoundError(Exception):
    """Raised when a user id does not exist."""


class UserEmailConflictError(Exception):
    """Raised when a create/update collides with an existing email."""


class UserUsernameConflictError(Exception):
    """Raised when a create/update collides with an existing username."""


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
        """Create a user. Raises UserEmailConflictError/UserUsernameConflictError on duplicates.

        Raises :class:`UserPermissionScopeError` if the prospective user does
        not satisfy the service's ``perm_filter`` (the principal's create scope).
        """
        user = User(
            email=payload.email,
            username=payload.username,
            enabled=payload.enabled,
            password=self._hash_password(payload.password),
        )
        if not self._perm_filter.matches(user):
            raise UserPermissionScopeError(str(payload.email))
        self._session.add(user)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
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

    async def get_many(
        self,
        user_ids: list[uuid.UUID],
    ) -> list[User | None]:
        """Retrieve users by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *user_ids*: the i-th entry is
        the :class:`User` for ``user_ids[i]`` or ``None`` when missing/out of
        scope. Duplicate ids are preserved (the same user appears at each
        position). An empty *user_ids* yields an empty list without hitting the
        DB.
        """
        if not user_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(User).where(User.id.in_(user_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, User] = {u.id: u for u in result.scalars().all()}
        return [by_id.get(uid) for uid in user_ids]

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
        """Partially update a user. Raises on missing/scoped-out user or unique conflict."""
        user = await self.get(user_id)
        if payload.email is not None:
            user.email = payload.email
        if payload.username is not None:
            user.username = payload.username
        if payload.enabled is not None:
            user.enabled = payload.enabled
        if payload.password is not None:
            user.password = self._hash_password(payload.password)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise _classify_integrity_error(exc, payload) from exc
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

    def _hash_password(self, plaintext: str | None) -> str | None:
        """Return a bcrypt salted hash of *plaintext*, or None to keep unset.

        The hash is never reversible to plaintext (AGENTS.md §9).
        """
        if plaintext is None:
            return None
        return hash_password(plaintext)

    def verify_password(self, plaintext: str, user: User) -> bool:
        """Return True iff *plaintext* matches the user's stored hash.

        Returns False when the user has no password set or the hash is malformed.
        """
        if not user.password:
            return False
        return verify_password(plaintext, user.password)

    async def get_by_username(self, username: str) -> User | None:
        """Look up a user by username, or None if no such user exists."""
        stmt = select(User).where(User.username == username)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def authenticate(
        self,
        username: str,
        password: str,
    ) -> User | None:
        """Return the enabled user matching *username*/*password*, else None.

        A disabled user never authenticates, even with a correct password.
        Constant-time bcrypt verification is delegated to the password utility.
        """
        user = await self.get_by_username(username)
        if user is None or not user.enabled or not user.password:
            return None
        if not verify_password(password, user.password):
            return None
        return user


def _classify_integrity_error(
    exc: IntegrityError,
    payload: UserCreate | UserUpdate,
) -> Exception:
    """Map a unique-constraint IntegrityError to the right domain conflict.

    asyncpg does not expose a structured constraint name on the DBAPI
    exception; the constraint name appears in the error message
    (``... violates unique constraint "ix_users_username"``). Match by it so
    callers see ``UserUsernameConflictError`` vs ``UserEmailConflictError``.
    """
    message = str(getattr(exc, "orig", exc))
    name = message.lower()
    if "username" in name:
        return UserUsernameConflictError(getattr(payload, "username", None) or "")
    return UserEmailConflictError(getattr(payload, "email", None) or "")


# Re-export for type-checking convenience in callers that import from the
# service namespace.
__all__ = [
    "User",
    "UserEmailConflictError",
    "UserNotFoundError",
    "UserPermissionScopeError",
    "UserService",
    "UserUsernameConflictError",
]
