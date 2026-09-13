"""Service layer for the :class:`StaticSecret` resource.

Backs the ``kind="static"`` secret provider. The sensitive ``value`` is
encrypted (JWE) at rest and never exposed through this CRUD surface — the read
model omits it entirely, and plaintext is revealed only through the
``/secret-values`` projection (whose single gate is USE on the parent provider).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.secret.secret_models import StaticSecret
from openhands.ev2.secret.secret_schemas import (
    StaticSecretBatchCreate,
    StaticSecretBatchDelete,
    StaticSecretBatchOp,
    StaticSecretBatchUpdate,
    StaticSecretCreate,
    StaticSecretRead,
    StaticSecretSearchFilter,
    StaticSecretUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class StaticSecretNotFoundError(Exception):
    """Raised when a static secret does not exist or is out of scope."""


class StaticSecretNameConflictError(Exception):
    """Raised when a create/update collides with an existing name."""


class StaticSecretPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class StaticSecretService:
    """CRUD over :class:`StaticSecret` rows, scoped by ``perm_filter``."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[StaticSecret] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, secret: StaticSecret) -> StaticSecretRead:
        """Build the API read model (omits the encrypted ``value``)."""
        return StaticSecretRead(
            id=secret.id,
            name=secret.name,
            creator_id=secret.creator_id,
            valid_at=secret.valid_at,
            expires_at=secret.expires_at,
            created_at=secret.created_at,
            updated_at=secret.updated_at,
        )

    async def create(
        self,
        payload: StaticSecretCreate,
        *,
        creator_id: uuid.UUID,
    ) -> StaticSecret:
        """Create a static secret, encrypting ``value`` at rest."""
        secret = StaticSecret(
            creator_id=creator_id,
            name=payload.name,
            value=self._enc.encrypt_value(payload.value.get_secret_value())
            if self._enc is not None
            else payload.value.get_secret_value(),
            valid_at=payload.valid_at,
            expires_at=payload.expires_at,
        )
        if not self._perm_filter.matches(secret):
            raise StaticSecretPermissionScopeError(payload.name)
        try:
            self._session.add(secret)
            await self._session.flush()
        except IntegrityError as exc:
            raise StaticSecretNameConflictError(payload.name) from exc
        await self._session.refresh(secret)
        return secret

    async def get(self, secret_id: uuid.UUID) -> StaticSecret:
        """Retrieve a static secret by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(StaticSecret).where(StaticSecret.id == secret_id)
        )
        result = await self._session.execute(stmt)
        secret = result.scalar_one_or_none()
        if secret is None:
            raise StaticSecretNotFoundError(str(secret_id))
        return secret

    async def get_many(self, secret_ids: list[uuid.UUID]) -> list[StaticSecret | None]:
        """Retrieve static secrets by ids, aligned with ``None`` for misses."""
        if not secret_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(StaticSecret).where(StaticSecret.id.in_(secret_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, StaticSecret] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(sid) for sid in secret_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: StaticSecretSearchFilter | None = None,
    ) -> tuple[list[StaticSecret], uuid.UUID | None]:
        """Search static secrets ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(StaticSecret).order_by(StaticSecret.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(StaticSecret.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: StaticSecretSearchFilter | None = None) -> int:
        """Count static secrets visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(StaticSecret))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    def _encrypted_value(self, value: str) -> str:
        """Encrypt a plaintext secret value for storage, or keep it as-is."""
        if self._enc is not None:
            return self._enc.encrypt_value(value)
        return value

    def _apply_update(
        self,
        secret: StaticSecret,
        payload: StaticSecretUpdate,
        fields: set[str],
    ) -> None:
        """Map a partial update onto an existing row, ignoring explicit nulls."""
        if "name" in fields and payload.name is not None:
            secret.name = payload.name
        if "value" in fields and payload.value is not None:
            secret.value = self._encrypted_value(payload.value.get_secret_value())
        if "valid_at" in fields:
            secret.valid_at = payload.valid_at
        if "expires_at" in fields:
            secret.expires_at = payload.expires_at

    async def update(
        self,
        secret_id: uuid.UUID,
        payload: StaticSecretUpdate,
    ) -> StaticSecret:
        """Partially update a static secret."""
        secret = await self.get(secret_id)
        self._apply_update(secret, payload, payload.model_fields_set)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise StaticSecretNameConflictError(str(secret_id)) from exc
        await self._session.refresh(secret)
        return secret

    async def delete(self, secret_id: uuid.UUID) -> None:
        """Delete a static secret."""
        secret = await self.get(secret_id)
        await self._session.delete(secret)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[StaticSecretBatchOp],
        perm_filters: dict[Action, SearchFilter[StaticSecret] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[StaticSecret | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[StaticSecret | None] = []
        for op in operations:
            if isinstance(op, StaticSecretBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, StaticSecretBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, StaticSecretBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: StaticSecretBatchCreate,
        perm_filters: dict[Action, SearchFilter[StaticSecret] | None],
        *,
        creator_id: uuid.UUID,
    ) -> StaticSecret:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await StaticSecretService(self._session, filt, encryption_service=self._enc).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: StaticSecretBatchUpdate,
        perm_filters: dict[Action, SearchFilter[StaticSecret] | None],
    ) -> StaticSecret:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await StaticSecretService(self._session, filt, encryption_service=self._enc).update(
            op.id, op.data
        )

    async def _batch_delete(
        self,
        op: StaticSecretBatchDelete,
        perm_filters: dict[Action, SearchFilter[StaticSecret] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await StaticSecretService(self._session, filt, encryption_service=self._enc).delete(op.id)
