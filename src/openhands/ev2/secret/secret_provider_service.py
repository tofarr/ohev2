"""Service layer for the governed :class:`SecretProvider` resource.

Follows the ``routers → services → repositories → models`` layering: the
service owns authorization scoping via ``perm_filter.filter_sql(...)``. The
sensitive ``data`` map is encrypted at rest — each value is wrapped to JWE
ciphertext on create/update and decrypted on read (the read schema then masks
by default, §13).
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import SecretProvider
from openhands.ev2.secret.secret_schemas import (
    SecretProviderBatchCreate,
    SecretProviderBatchDelete,
    SecretProviderBatchOp,
    SecretProviderBatchUpdate,
    SecretProviderCreate,
    SecretProviderRead,
    SecretProviderSearchFilter,
    SecretProviderUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter
from openhands.ev2.util.secret_serialization import encrypt_secret_map


class SecretProviderNotFoundError(Exception):
    """Raised when a provider does not exist or is out of scope."""


class SecretProviderPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SecretProviderService:
    """CRUD over :class:`SecretProvider` rows, scoped by ``perm_filter``."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SecretProvider] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, provider: SecretProvider) -> SecretProviderRead:
        """Build the API read model from an ORM row.

        Stored ``data`` values are JWE ciphertext; they are decrypted here so
        the read schema masks (or exposes, with the §13 context flag) the
        plaintext.
        """
        return SecretProviderRead(
            id=provider.id,
            kind=provider.kind,
            data=self._decrypt_data(provider.data),
            creator_id=provider.creator_id,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
        )

    def _decrypt_data(self, data: dict[str, Any]) -> dict[str, object]:
        return (
            {
                str(key): self._enc.decrypt_value(str(item)) if self._enc is not None else str(item)
                for key, item in data.items()
            }
            if data
            else {}
        )

    def _encrypt_data(self, data: dict[str, SecretStr]) -> dict[str, str]:
        return encrypt_secret_map(self._enc, data)

    async def create(
        self,
        payload: SecretProviderCreate,
        *,
        creator_id: uuid.UUID,
    ) -> SecretProvider:
        """Create a secret provider, encrypting ``data`` at rest."""
        raw = payload.data
        provider = SecretProvider(
            creator_id=creator_id,
            kind=payload.kind,
            data=self._encrypt_data(raw),
        )
        if not self._perm_filter.matches(provider):
            raise SecretProviderPermissionScopeError(payload.kind)
        self._session.add(provider)
        await self._session.flush()
        await self._session.refresh(provider)
        return provider

    async def get(self, provider_id: uuid.UUID) -> SecretProvider:
        """Retrieve a provider by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(SecretProvider).where(SecretProvider.id == provider_id)
        )
        result = await self._session.execute(stmt)
        provider = result.scalar_one_or_none()
        if provider is None:
            raise SecretProviderNotFoundError(str(provider_id))
        return provider

    async def get_many(self, provider_ids: list[uuid.UUID]) -> list[SecretProvider | None]:
        """Retrieve providers by ids, positionally aligned with ``None`` for misses."""
        if not provider_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SecretProvider).where(SecretProvider.id.in_(provider_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, SecretProvider] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(pid) for pid in provider_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SecretProviderSearchFilter | None = None,
    ) -> tuple[list[SecretProvider], uuid.UUID | None]:
        """Search providers ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(SecretProvider).order_by(SecretProvider.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SecretProvider.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: SecretProviderSearchFilter | None = None) -> int:
        """Count providers visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SecretProvider))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        provider_id: uuid.UUID,
        payload: SecretProviderUpdate,
    ) -> SecretProvider:
        """Partially update a secret provider."""
        provider = await self.get(provider_id)
        if "data" in payload.model_fields_set and payload.data is not None:
            provider.data = self._encrypt_data(payload.data)
        await self._session.flush()
        await self._session.refresh(provider)
        return provider

    async def delete(self, provider_id: uuid.UUID) -> None:
        """Delete a secret provider."""
        provider = await self.get(provider_id)
        try:
            await self._session.delete(provider)
            await self._session.flush()
        except IntegrityError as exc:
            raise SecretProviderPermissionScopeError(str(provider_id)) from exc

    async def apply_batch(
        self,
        operations: list[SecretProviderBatchOp],
        perm_filters: dict[Action, SearchFilter[SecretProvider] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[SecretProvider | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[SecretProvider | None] = []
        for op in operations:
            if isinstance(op, SecretProviderBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, SecretProviderBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, SecretProviderBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: SecretProviderBatchCreate,
        perm_filters: dict[Action, SearchFilter[SecretProvider] | None],
        *,
        creator_id: uuid.UUID,
    ) -> SecretProvider:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await SecretProviderService(
            self._session, filt, encryption_service=self._enc
        ).create(op.data, creator_id=creator_id)

    async def _batch_update(
        self,
        op: SecretProviderBatchUpdate,
        perm_filters: dict[Action, SearchFilter[SecretProvider] | None],
    ) -> SecretProvider:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await SecretProviderService(
            self._session, filt, encryption_service=self._enc
        ).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: SecretProviderBatchDelete,
        perm_filters: dict[Action, SearchFilter[SecretProvider] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await SecretProviderService(self._session, filt, encryption_service=self._enc).delete(op.id)
