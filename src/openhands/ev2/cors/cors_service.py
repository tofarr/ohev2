"""Service for the CORS allow-list feature.

CRUD for the ``allowed_origins`` table, plus an in-memory cache the CORS
middleware reads on every cross-origin request. Mutations (create/delete)
invalidate the cache so changes take effect immediately without a restart.
"""

from __future__ import annotations

import time
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.cors.cors_models import AllowedOrigin
from openhands.ev2.cors.cors_schemas import (
    AllowedOriginBatchCreate,
    AllowedOriginBatchDelete,
    AllowedOriginBatchOp,
)
from openhands.ev2.db import get_session_factory
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter


class CorsError(Exception):
    """Base error for the CORS allow-list feature."""


class AllowedOriginConflictError(CorsError):
    """The origin is already registered."""


class AllowedOriginNotFoundError(CorsError):
    """The origin id does not exist."""


class BatchPermissionDeniedError(CorsError):
    """Raised when a batch operation's action is not granted to the principal."""


# In-memory cache of the allowed-origin set. The middleware reads this on the
# hot path (every cross-origin request); mutations reset it via
# `reset_cors_cache`. A TTL guards against stale state if a process mutation
# bypassed the service (e.g. a manual DB write).
_cache: tuple[set[str], float] | None = None
_CACHE_TTL_SECONDS = 30.0


def reset_cors_cache() -> None:
    """Invalidate the in-memory allowed-origin cache.

    Called after create/delete so the middleware sees the new set without
    waiting for the TTL to expire.
    """
    global _cache
    _cache = None


async def get_allowed_origins_cached() -> set[str]:
    """Return the cached allowed-origin set, refreshing from the DB on TTL expiry.

    Used by the CORS middleware on the hot path; avoids a DB hit per request
    for the TTL window. Returns a copy so callers cannot mutate the cache.
    """
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[1] < _CACHE_TTL_SECONDS:
        return set(_cache[0])
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(AllowedOrigin.origin))
        origins = set(result.scalars().all())
    _cache = (origins, now)
    return set(origins)


class CorsService:
    """CRUD for the global CORS allowed-origin list."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_allowed_origins(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
    ) -> tuple[list[AllowedOrigin], uuid.UUID | None]:
        """Return a page of allowed origins ordered by id (cursor pagination)."""
        stmt = select(AllowedOrigin).order_by(AllowedOrigin.id)
        if cursor is not None:
            stmt = stmt.where(AllowedOrigin.id > cursor)
        stmt = stmt.limit(limit + 1)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        # Cursor is the id of the last returned row; None when no more remain.
        next_cursor = rows[limit - 1].id if len(rows) > limit else None
        return rows[:limit], next_cursor

    async def create_allowed_origin(self, origin: str) -> AllowedOrigin:
        """Register a permitted origin. Raises on duplicate."""
        row = AllowedOrigin(origin=origin)
        self._session.add(row)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise AllowedOriginConflictError(origin) from exc
        reset_cors_cache()
        return row

    async def get_allowed_origin(self, origin_id: uuid.UUID) -> AllowedOrigin:
        """Retrieve a permitted origin by id. Raises if not found."""
        row = await self._session.get(AllowedOrigin, origin_id)
        if row is None:
            raise AllowedOriginNotFoundError(str(origin_id))
        return row

    async def get_many(
        self,
        origin_ids: list[uuid.UUID],
    ) -> list[AllowedOrigin | None]:
        """Retrieve permitted origins by ids in a single query.

        Returns a list positionally aligned with *origin_ids*: the i-th entry is
        the :class:`AllowedOrigin` for ``origin_ids[i]`` or ``None`` when
        missing. Duplicate ids are preserved. An empty *origin_ids* yields an
        empty list without hitting the DB.
        """
        if not origin_ids:
            return []
        result = await self._session.execute(
            select(AllowedOrigin).where(AllowedOrigin.id.in_(origin_ids))
        )
        by_id: dict[uuid.UUID, AllowedOrigin] = {o.id: o for o in result.scalars().all()}
        return [by_id.get(oid) for oid in origin_ids]

    async def delete_allowed_origin(self, origin_id: uuid.UUID) -> None:
        """Remove a permitted origin by id. Raises if not found."""
        row = await self.get_allowed_origin(origin_id)
        await self._session.delete(row)
        await self._session.flush()
        reset_cors_cache()

    async def apply_batch(
        self,
        operations: list[AllowedOriginBatchOp],
        perm_filters: dict[Action, SearchFilter[AllowedOrigin] | None],
    ) -> list[AllowedOrigin | None]:
        """Apply a mix of create/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        an action with a ``None`` filter is denied
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic: a failure of
        any operation rolls back the entire batch). Returns results aligned with
        *operations*: the created :class:`AllowedOrigin` for create ops, ``None``
        for delete ops.
        """
        results: list[AllowedOrigin | None] = []
        for op in operations:
            if isinstance(op, AllowedOriginBatchCreate):
                if perm_filters.get(Action.CREATE) is None:
                    raise BatchPermissionDeniedError("create")
                results.append(await self.create_allowed_origin(op.data.origin))
            elif isinstance(op, AllowedOriginBatchDelete):
                if perm_filters.get(Action.DELETE) is None:
                    raise BatchPermissionDeniedError("delete")
                await self.delete_allowed_origin(op.id)
                results.append(None)
        return results
