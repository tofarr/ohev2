"""The ``kind="static"`` :class:`SecretProvider` implementation.

Reads from the DB-backed :class:`StaticSecret` store. ``internal_id`` for this
provider is the **stringified row UUID** — it is generated on the
:class:`SecretValue` at read time (not stored as an explicit column), while
``name`` is the human-readable handle. ``value`` is decrypted at read time via
the encryption service.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService
from openhands.ev2.secret.secret_models import StaticSecret
from openhands.ev2.secret.secret_provider import SecretProvider
from openhands.ev2.secret.secret_value import SecretValue


class StaticSecretProvider(SecretProvider):
    """A retrieval-only provider over the :class:`StaticSecret` table."""

    def __init__(self, enc: EncryptionService) -> None:
        self._enc = enc

    async def get(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        internal_id: str,
    ) -> SecretValue | None:
        try:
            secret_id = uuid.UUID(internal_id)
        except ValueError:
            return None
        result = await session.execute(select(StaticSecret).where(StaticSecret.id == secret_id))
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return self._to_value(provider_id, row)

    async def batch_get(
        self,
        session: AsyncSession,
        provider_ids: list[uuid.UUID],
        internal_ids: list[str],
    ) -> list[SecretValue | None]:
        if not internal_ids:
            return []
        if len(provider_ids) != len(internal_ids):
            raise ValueError("provider_ids and internal_ids must have equal length")
        results: list[SecretValue | None] = []
        for provider_id, internal_id in zip(provider_ids, internal_ids, strict=True):
            results.append(await self.get(session, provider_id, internal_id))
        return results

    async def search(
        self,
        session: AsyncSession,
        provider_id: uuid.UUID,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[SecretValue], str | None]:
        stmt = select(StaticSecret).order_by(StaticSecret.id)
        if cursor is not None:
            stmt = stmt.where(StaticSecret.id > _cursor_uuid(cursor))
        stmt = stmt.limit(limit)
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        values = [self._to_value(provider_id, row) for row in rows]
        next_cursor = str(values[-1].internal_id) if len(values) == limit else None
        return values, next_cursor

    def _to_value(self, provider_id: uuid.UUID, row: StaticSecret) -> SecretValue:
        return SecretValue.make(
            provider_id=provider_id,
            internal_id=str(row.id),
            name=row.name,
            value=self._enc.decrypt_value(row.value),
            valid_at=row.valid_at,
            expires_at=row.expires_at,
        )


def _cursor_uuid(value: str) -> uuid.UUID:
    return uuid.UUID(value)
