"""Service layer for the user feature.

Services contain business logic; repositories contain data access. This module
exposes a thin `UserService` over SQLAlchemy async sessions per AGENTS.md §4.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ohev.user.models.user import User
from ohev.user.schemas import UserCreate, UserUpdate


class UserNotFoundError(Exception):
    """Raised when a user id does not exist."""


class UserEmailConflictError(Exception):
    """Raised when a create/update collides with an existing email."""


class UserService:
    """CRUD operations over users.

    The service is constructed per request with the request-scoped session; it
    holds no mutable state of its own.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, payload: UserCreate) -> User:
        """Create a user. Raises UserEmailConflictError on duplicate email."""
        user = User(email=payload.email)
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

    async def get(self, user_id: uuid.UUID) -> User:
        """Retrieve a user by id. Raises UserNotFoundError if missing."""
        user = await self._session.get(User, user_id)
        if user is None:
            raise UserNotFoundError(str(user_id))
        return user

    async def search_users(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        email_contains: str | None = None,
        created_at_gte: datetime | None = None,
        created_at_lt: datetime | None = None,
    ) -> tuple[list[User], uuid.UUID | None]:
        """Search users ordered by id, keyed-pagination via cursor.

        Optional filters: case-insensitive email substring, created_at bounds.
        Returns (users, next_cursor). next_cursor is None when exhausted.
        """
        stmt = select(User).order_by(User.id)
        if email_contains is not None:
            stmt = stmt.where(User.email.ilike(f"%{email_contains}%"))
        if created_at_gte is not None:
            # DB stores naive timestamps (server_default func.now()); strip tz
            # from aware datetimes to avoid asyncpg offset mismatch.
            gte = created_at_gte.replace(tzinfo=None) if created_at_gte.tzinfo else created_at_gte
            stmt = stmt.where(User.created_at >= gte)
        if created_at_lt is not None:
            lt = created_at_lt.replace(tzinfo=None) if created_at_lt.tzinfo else created_at_lt
            stmt = stmt.where(User.created_at < lt)
        if cursor is not None:
            stmt = stmt.where(User.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        users = list(result.scalars().all())
        next_cursor = users[-1].id if len(users) == limit else None
        return users, next_cursor

    async def update(self, user_id: uuid.UUID, payload: UserUpdate) -> User:
        """Partially update a user. Raises on missing user or email conflict."""
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

    async def delete(self, user_id: uuid.UUID) -> None:
        """Delete a user. Raises UserNotFoundError if missing."""
        user = await self.get(user_id)
        await self._session.delete(user)
        await self._session.flush()

    async def count(self) -> int:
        """Total user count (used by tests/fixtures)."""
        stmt = select(func.count()).select_from(User)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())
