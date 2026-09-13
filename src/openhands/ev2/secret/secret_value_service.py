"""Read-only service over :class:`SecretProvider` implementations.

Serves the ``/secret-values`` projection: a plaintext reveal surface gated by a
**single** USE permission on the parent provider (AGENTS.md §12). Compiled
against the :class:`SecretProvider` ABC so the implementation works unchanged
once AWS / 1Password providers land.

Composite ids are ``{provider_id}/{internal_id}`` (:class:`SecretValue.split_id`).
"""

from __future__ import annotations

import contextlib
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_provider import SecretProviderSearch
from openhands.ev2.secret.secret_provider_registry import SecretProviderCache
from openhands.ev2.secret.secret_value import SecretValue
from openhands.ev2.util.search_filter import SearchFilter


class SecretValueNotFoundError(Exception):
    """Raised when a secret value is missing or out of scope."""


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
    ) -> SecretProviderSearch:
        stmt = provider_filter.filter_sql(
            select(SecretProvider).where(SecretProvider.id == provider_id)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise SecretValueNotFoundError(str(provider_id))
        provider = self._cache.get(row.id, row.kind, row.data)
        return SecretProviderSearch(provider_id=row.id, provider=provider)

    async def get(
        self,
        composite_id: str,
        provider_filter: SearchFilter[SecretProvider],
    ) -> SecretValue:
        """Return one secret value by composite id, or raise :class:`SecretValueNotFoundError`."""
        try:
            provider_id, internal_id = SecretValue.split_id(composite_id)
        except ValueError as exc:
            raise SecretValueNotFoundError(composite_id) from exc
        handle = await self._resolve(provider_id, provider_filter)
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
        resolved: dict[uuid.UUID, SecretProviderSearch],
    ) -> None:
        """Fetch each provider's batch and scatter values back by index."""
        for provider_id, indexes in indexes_by_provider.items():
            handle = resolved.get(provider_id)
            if handle is None:
                continue
            internal_ids = internal_by_provider[provider_id]
            values = await handle.provider.batch_get(
                self._session, [handle.provider_id] * len(internal_ids), internal_ids
            )
            for index, value in zip(indexes, values, strict=True):
                if value is not None:
                    results[index] = value

    async def get_many(
        self,
        composite_ids: list[str],
        provider_filter: SearchFilter[SecretProvider],
    ) -> list[SecretValue | None]:
        """Return secret values aligned with ``composite_ids`` (``None`` for misses)."""
        if not composite_ids:
            return []
        parsed = self._split_composite_ids(composite_ids)
        # Group by provider so we issue one client batch per provider.
        indexes_by_provider, internal_by_provider = self._group_by_provider(parsed)
        resolved: dict[uuid.UUID, SecretProviderSearch] = {}
        for provider_id in indexes_by_provider:
            with contextlib.suppress(SecretValueNotFoundError):
                resolved[provider_id] = await self._resolve(provider_id, provider_filter)
        results: list[SecretValue | None] = [None] * len(composite_ids)
        await self._scatter_grouped_values(
            results, indexes_by_provider, internal_by_provider, resolved
        )
        return results

    async def search(
        self,
        provider_id: uuid.UUID,
        provider_filter: SearchFilter[SecretProvider],
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        """Page secrets from *provider_id*, ordered by internal id."""
        handle = await self._resolve(provider_id, provider_filter)
        return await handle.provider.search(
            self._session, handle.provider_id, limit=limit, cursor=cursor
        )
