"""Read-only service over :class:`SecretProvider` implementations.

Serves the ``/secret-values`` projection: a plaintext reveal surface gated by a
**single** USE permission on the parent provider (AGENTS.md §12). Compiled
against the :class:`SecretProvider` ABC so the implementation works unchanged
once AWS / 1Password providers land.

Composite ids are ``{provider_id}/{internal_id}`` (:class:`SecretValue.split_id`).

For the ``oauth`` kind, the ``internal_id`` encodes
``{oauth_provider_id}/{oauth_session_id}`` (sub-issue #145). Before delegating
to the provider, this service applies the caller's ``OAuthSession`` USE filter
as a pre-check — fail-closed (404) when the session is out of scope or the
filter is ``None`` (no grant). This satisfies the per-session USE requirement
from issue #141 without changing the ``SecretProvider`` ABC.
"""

from __future__ import annotations

import contextlib
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_provider import SecretProviderSearch
from openhands.ev2.secret.secret_provider_registry import OAUTH_PROVIDER_KIND, SecretProviderCache
from openhands.ev2.secret.secret_value import SecretValue
from openhands.ev2.util.search_filter import SearchFilter


class SecretValueNotFoundError(Exception):
    """Raised when a secret value is missing or out of scope."""


def _parse_cursor(cursor: str) -> uuid.UUID | None:
    """Parse a pagination cursor into a UUID, returning ``None`` on invalid input."""
    try:
        return uuid.UUID(cursor)
    except ValueError:
        return None


class SecretValueSession:
    """Per-provider read handle tying a provider row to its implementation."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._cache = SecretProviderCache(encryption_service or get_encryption_service())

    async def _resolve(
        self,
        provider_id: uuid.UUID,
        provider_filter: SearchFilter[SecretProvider],
    ) -> tuple[SecretProviderSearch, str]:
        """Resolve the provider row + implementation, returning ``(handle, kind)``."""
        stmt = provider_filter.filter_sql(
            select(SecretProvider).where(SecretProvider.id == provider_id)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise SecretValueNotFoundError(str(provider_id))
        provider = self._cache.get(row.id, row.kind, row.data)
        return SecretProviderSearch(provider_id=row.id, provider=provider), row.kind

    def _parse_oauth_session_id(self, internal_id: str) -> uuid.UUID | None:
        """Extract the ``oauth_session_id`` from an oauth composite internal id."""
        parts = internal_id.split("/", 1)
        if len(parts) != 2:
            return None
        try:
            return uuid.UUID(parts[1])
        except ValueError:
            return None

    async def _check_oauth_session_use(
        self,
        session_filter: SearchFilter[Any] | None,
        oauth_session_id: uuid.UUID,
    ) -> None:
        """Fail-closed when the caller lacks USE on the specific OAuthSession."""
        if session_filter is None:
            raise SecretValueNotFoundError(str(oauth_session_id))
        from openhands.ev2.oauth.oauth_session_models import OAuthSession

        stmt = session_filter.filter_sql(
            select(OAuthSession.id).where(OAuthSession.id == oauth_session_id)
        )
        result = await self._session.execute(stmt)
        if result.scalar_one_or_none() is None:
            raise SecretValueNotFoundError(str(oauth_session_id))

    async def get(
        self,
        composite_id: str,
        provider_filter: SearchFilter[SecretProvider],
        *,
        session_filter: SearchFilter[Any] | None = None,
    ) -> SecretValue:
        """Return one secret value by composite id, or raise :class:`SecretValueNotFoundError`."""
        try:
            provider_id, internal_id = SecretValue.split_id(composite_id)
        except ValueError as exc:
            raise SecretValueNotFoundError(composite_id) from exc
        handle, kind = await self._resolve(provider_id, provider_filter)
        if kind == OAUTH_PROVIDER_KIND:
            oauth_session_id = self._parse_oauth_session_id(internal_id)
            if oauth_session_id is None:
                raise SecretValueNotFoundError(composite_id)
            await self._check_oauth_session_use(session_filter, oauth_session_id)
        value = await handle.provider.get(self._session, handle.provider_id, internal_id)
        if value is None:
            raise SecretValueNotFoundError(composite_id)
        return value

    def _split_composite_ids(self, composite_ids: list[str]) -> list[tuple[uuid.UUID, str] | None]:
        """Parse composite ids; entries whose format is invalid become ``None``."""
        parsed: list[tuple[uuid.UUID, str] | None] = []
        for cid in composite_ids:
            try:
                parsed.append(SecretValue.split_id(cid))
            except ValueError:
                parsed.append(None)
        return parsed

    def _group_by_provider(
        self, parsed: list[tuple[uuid.UUID, str] | None]
    ) -> tuple[dict[uuid.UUID, list[int]], dict[uuid.UUID, list[str]]]:
        """Bucket request indexes and internal ids by provider id."""
        indexes: dict[uuid.UUID, list[int]] = {}
        internal_by_provider: dict[uuid.UUID, list[str]] = {}
        for index, pair in enumerate(parsed):
            if pair is None:
                continue
            provider_id, internal_id = pair
            indexes.setdefault(provider_id, []).append(index)
            internal_by_provider.setdefault(provider_id, []).append(internal_id)
        return indexes, internal_by_provider

    async def _scatter_grouped_values(
        self,
        results: list[SecretValue | None],
        indexes_by_provider: dict[uuid.UUID, list[int]],
        internal_by_provider: dict[uuid.UUID, list[str]],
        resolved: dict[uuid.UUID, tuple[SecretProviderSearch, str]],
        session_filter: SearchFilter[Any] | None,
    ) -> None:
        """Fetch each provider's batch and scatter values back by index."""
        for provider_id, indexes in indexes_by_provider.items():
            entry = resolved.get(provider_id)
            if entry is None:
                continue
            handle, kind = entry
            internal_ids = internal_by_provider[provider_id]
            if kind == OAUTH_PROVIDER_KIND:
                await self._scatter_oauth_batch(
                    handle, indexes, internal_ids, results, session_filter
                )
            else:
                values = await handle.provider.batch_get(
                    self._session, [handle.provider_id] * len(internal_ids), internal_ids
                )
                for index, value in zip(indexes, values, strict=True):
                    if value is not None:
                        results[index] = value

    async def _scatter_oauth_batch(
        self,
        handle: SecretProviderSearch,
        indexes: list[int],
        internal_ids: list[str],
        results: list[SecretValue | None],
        session_filter: SearchFilter[Any] | None,
    ) -> None:
        """Pre-check USE on each oauth session, then batch-fetch only authorized ones."""
        authorized_idx: list[int] = []
        authorized_iids: list[str] = []
        for idx, iid in zip(indexes, internal_ids, strict=True):
            oauth_session_id = self._parse_oauth_session_id(iid)
            if oauth_session_id is None:
                continue
            try:
                await self._check_oauth_session_use(session_filter, oauth_session_id)
            except SecretValueNotFoundError:
                continue
            authorized_idx.append(idx)
            authorized_iids.append(iid)
        if not authorized_iids:
            return
        values = await handle.provider.batch_get(
            self._session, [handle.provider_id] * len(authorized_iids), authorized_iids
        )
        for index, value in zip(authorized_idx, values, strict=True):
            if value is not None:
                results[index] = value

    async def get_many(
        self,
        composite_ids: list[str],
        provider_filter: SearchFilter[SecretProvider],
        *,
        session_filter: SearchFilter[Any] | None = None,
    ) -> list[SecretValue | None]:
        """Return secret values aligned with ``composite_ids`` (``None`` for misses)."""
        if not composite_ids:
            return []
        parsed = self._split_composite_ids(composite_ids)
        # Group by provider so we issue one client batch per provider.
        indexes_by_provider, internal_by_provider = self._group_by_provider(parsed)
        resolved: dict[uuid.UUID, tuple[SecretProviderSearch, str]] = {}
        for provider_id in indexes_by_provider:
            with contextlib.suppress(SecretValueNotFoundError):
                resolved[provider_id] = await self._resolve(provider_id, provider_filter)
        results: list[SecretValue | None] = [None] * len(composite_ids)
        await self._scatter_grouped_values(
            results, indexes_by_provider, internal_by_provider, resolved, session_filter
        )
        return results

    async def search(
        self,
        provider_id: uuid.UUID,
        provider_filter: SearchFilter[SecretProvider],
        *,
        limit: int = 50,
        cursor: str | None = None,
        session_filter: SearchFilter[Any] | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        """Page secrets from *provider_id*, ordered by internal id."""
        handle, kind = await self._resolve(provider_id, provider_filter)
        if kind == OAUTH_PROVIDER_KIND:
            return await self._search_oauth(handle, session_filter, limit=limit, cursor=cursor)
        return await handle.provider.search(
            self._session, handle.provider_id, limit=limit, cursor=cursor
        )

    async def _search_oauth(
        self,
        handle: SecretProviderSearch,
        session_filter: SearchFilter[Any] | None,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        """Scope OAuthSession rows by the caller's USE filter, then resolve tokens."""
        if session_filter is None:
            return [], None
        from openhands.ev2.oauth.oauth_session_models import OAuthSession

        stmt = session_filter.filter_sql(select(OAuthSession).order_by(OAuthSession.id))
        if cursor is not None:
            cursor_uuid = _parse_cursor(cursor)
            if cursor_uuid is not None:
                stmt = stmt.where(OAuthSession.id > cursor_uuid)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        if not rows:
            return [], None
        internal_ids = [f"{r.oauth_provider_id}/{r.id}" for r in rows]
        values = await handle.provider.batch_get(
            self._session, [handle.provider_id] * len(internal_ids), internal_ids
        )
        out = [v for v in values if v is not None]
        next_cursor = str(rows[-1].id) if len(rows) == limit else None
        return out, next_cursor
