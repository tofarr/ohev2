"""Service layer for the api_key feature.

Services contain business logic; repositories contain data access. This module
exposes a thin ``ApiKeyService`` over SQLAlchemy async sessions per AGENTS.md
§4. The service holds the effective ``perm_filter`` (the search filter from the
centralized permission checker) as a field, set at construction, that scopes
the SQL to rows the principal is allowed to see/modify; :meth:`create`
validates the incoming item against it in memory (AGENTS.md §9 — authorization
enforced in services, not just routers). Key minting is delegated to
:class:`TokenService` so the raw ``oh_...`` value and its backing row stay
consistent.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.api_key.api_key_schemas import (
    ApiKeyBatchCreate,
    ApiKeyBatchDelete,
    ApiKeyBatchOp,
    ApiKeyBatchUpdate,
    ApiKeyCreate,
    ApiKeySearchFilter,
    ApiKeyUpdate,
)
from openhands.ev2.auth.auth_models import ApiKey
from openhands.ev2.auth.auth_tokens import TokenService
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class ApiKeyNotFoundError(Exception):
    """Raised when an API key id does not exist."""


class ApiKeyPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class ApiKeyService:
    """CRUD operations over API keys.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[ApiKey] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: ApiKeyCreate, *, user_id: uuid.UUID) -> tuple[str, ApiKey]:
        """Mint an API key and persist its backing row.

        Returns (raw_key, row). *user_id* is the current principal, never read
        from the payload (AGENTS.md §9). Raises
        :class:`ApiKeyPermissionScopeError` if the prospective key does not
        satisfy the service's ``perm_filter`` (the principal's create scope).
        """
        # Validate scope before minting: the perm_filter is the principal's
        # create grant reduced to a row predicate. Checked in-memory so a
        # principal scoped to their own keys cannot mint one for another user.
        # The key_hash/prefix are placeholders; the real values are minted below
        # and the final row is re-checked against the scope.
        prospective = ApiKey(
            key_hash="placeholder",
            prefix="placeholder",
            user_id=user_id,
            name=payload.name,
            enabled=payload.enabled,
            expires_at=payload.expires_at,
        )
        if not self._perm_filter.matches(prospective):
            raise ApiKeyPermissionScopeError(str(user_id))

        token_service = TokenService(self._session)
        raw_key, row = await token_service.create_api_key(
            user_id,
            name=payload.name,
            enabled=payload.enabled,
            expires_at=payload.expires_at,
        )
        # Re-validate the persisted row against the scope in case the filter
        # depends on server-side defaults (id/created_at) — matches() on the
        # final row is the authoritative scope check.
        if not self._perm_filter.matches(row):
            # Roll back the minted row so a scoped-out create leaves nothing.
            await self._session.rollback()
            raise ApiKeyPermissionScopeError(str(user_id))
        await self._session.refresh(row)
        return raw_key, row

    async def get(self, api_key_id: uuid.UUID) -> ApiKey:
        """Retrieve an API key by id, scoped by ``perm_filter``.

        Raises :class:`ApiKeyNotFoundError` if the key is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(ApiKey).where(ApiKey.id == api_key_id))
        result = await self._session.execute(stmt)
        api_key = result.scalar_one_or_none()
        if api_key is None:
            raise ApiKeyNotFoundError(str(api_key_id))
        return api_key

    async def get_many(
        self,
        api_key_ids: list[uuid.UUID],
    ) -> list[ApiKey | None]:
        """Retrieve API keys by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *api_key_ids*: the i-th entry
        is the :class:`ApiKey` for ``api_key_ids[i]`` or ``None`` when
        missing/out of scope. Duplicate ids are preserved. An empty
        *api_key_ids* yields an empty list without hitting the DB.
        """
        if not api_key_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(ApiKey).where(ApiKey.id.in_(api_key_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, ApiKey] = {k.id: k for k in result.scalars().all()}
        return [by_id.get(kid) for kid in api_key_ids]

    async def search_api_keys(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: ApiKeySearchFilter | None = None,
    ) -> tuple[list[ApiKey], uuid.UUID | None]:
        """Search API keys ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (keys, next_cursor). next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(ApiKey).order_by(ApiKey.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(ApiKey.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        keys = list(result.scalars().all())
        next_cursor = keys[-1].id if len(keys) == limit else None
        return keys, next_cursor

    async def update(self, api_key_id: uuid.UUID, payload: ApiKeyUpdate) -> ApiKey:
        """Partially update an API key. Raises on missing/scoped-out key."""
        api_key = await self.get(api_key_id)
        if payload.name is not None:
            api_key.name = payload.name
        if payload.enabled is not None:
            api_key.enabled = payload.enabled
        if payload.expires_at is not None:
            api_key.expires_at = payload.expires_at
        await self._session.flush()
        await self._session.refresh(api_key)
        return api_key

    async def delete(self, api_key_id: uuid.UUID) -> None:
        """Delete an API key. Raises ApiKeyNotFoundError if missing or out of scope.

        Deleting the row revokes the key: ``TokenService.authenticate`` rejects
        a key whose hash has no live backing row.
        """
        api_key = await self.get(api_key_id)
        await self._session.delete(api_key)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[ApiKeyBatchOp],
        perm_filters: dict[Action, SearchFilter[ApiKey] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[ApiKey | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the key for create/update, ``None``
        for delete. Batch creates do not return the minted JWE token.
        *user_id* is the current principal and is used as the subject of any
        created key (never read from the payload).
        """
        results: list[ApiKey | None] = []
        for op in operations:
            if isinstance(op, ApiKeyBatchCreate):
                results.append(await self._batch_create(op, perm_filters, user_id=user_id))
            elif isinstance(op, ApiKeyBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, ApiKeyBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: ApiKeyBatchCreate,
        perm_filters: dict[Action, SearchFilter[ApiKey] | None],
        *,
        user_id: uuid.UUID,
    ) -> ApiKey:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        # A per-operation ApiKeyService so the create's perm_filter matches the
        # operation's action, not the batch endpoint's single action. The raw
        # key is discarded: batch creates do not surface secrets.
        _key, row = await ApiKeyService(self._session, filt).create(op.data, user_id=user_id)
        return row

    async def _batch_update(
        self,
        op: ApiKeyBatchUpdate,
        perm_filters: dict[Action, SearchFilter[ApiKey] | None],
    ) -> ApiKey:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await ApiKeyService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: ApiKeyBatchDelete,
        perm_filters: dict[Action, SearchFilter[ApiKey] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await ApiKeyService(self._session, filt).delete(op.id)

    async def count(
        self,
        search_filter: ApiKeySearchFilter | None = None,
    ) -> int:
        """Total API-key count, scoped by the service's ``perm_filter`` and the
        optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(ApiKey))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())


__all__ = [
    "ApiKey",
    "ApiKeyNotFoundError",
    "ApiKeyPermissionScopeError",
    "ApiKeyService",
    "BatchPermissionDeniedError",
]
