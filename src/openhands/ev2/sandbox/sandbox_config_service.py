"""Service layer for the DB-backed sandbox config resource.

CRUD over :class:`SandboxConfig` (the durable intent for a sandbox). The
``session_api_key`` is minted on create and encrypted at rest (JWE ciphertext,
same pattern as :class:`StoredProviderConnection.api_key`). It is never exposed
in the API read model — the live sandbox service decrypts it when reconciling.

The service delegates to the :class:`SandboxService` (the polymorphic
reconciler) when ``enabled`` changes — the DB row is the source of truth, the
service boots/stops the live sandbox to match.
"""

from __future__ import annotations

import secrets
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_config_schemas import (
    SandboxConfigBatchCreate,
    SandboxConfigBatchDelete,
    SandboxConfigBatchOp,
    SandboxConfigBatchUpdate,
    SandboxConfigCreate,
    SandboxConfigRead,
    SandboxConfigSearchFilter,
    SandboxConfigUpdate,
)
from openhands.ev2.sandbox.sandbox_session import hash_session_api_key
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxConfigNotFoundError(Exception):
    """Raised when a sandbox config does not exist or is out of scope."""


class SandboxConfigPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class SandboxTemplateNotFoundError(Exception):
    """Raised when the template referenced by a config does not exist."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


def _generate_session_api_key() -> str:
    """Mint a random session API key for a sandbox."""
    return secrets.token_urlsafe(32)


class SandboxConfigService:
    """CRUD over :class:`SandboxConfig`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SandboxConfig] = ALL,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    def to_read(self, config: SandboxConfig) -> SandboxConfigRead:
        """Build the API read model (omits ``session_api_key``)."""
        return SandboxConfigRead(
            id=config.id,
            creator_id=config.creator_id,
            sandbox_template_id=config.sandbox_template_id,
            enabled=config.enabled,
            sandbox_snapshot_id=config.sandbox_snapshot_id,
            expires_at=config.expires_at,
            snapshot_on_deactivate=config.snapshot_on_deactivate,
            meta=config.meta,
            created_at=config.created_at,
            updated_at=config.updated_at,
        )

    async def _get_template(self, template_id: uuid.UUID) -> SandboxTemplate:
        result = await self._session.execute(
            select(SandboxTemplate).where(SandboxTemplate.id == template_id)
        )
        template = result.scalar_one_or_none()
        if template is None:
            raise SandboxTemplateNotFoundError(str(template_id))
        return template

    async def create(
        self,
        payload: SandboxConfigCreate,
        *,
        creator_id: uuid.UUID,
    ) -> SandboxConfig:
        """Create a sandbox config with an encrypted session API key."""
        template = await self._get_template(payload.sandbox_template_id)
        snapshot_on_deactivate = (
            payload.snapshot_on_deactivate
            if payload.snapshot_on_deactivate is not None
            else template.snapshot_on_deactivate
        )
        plaintext_key = _generate_session_api_key()
        config = SandboxConfig(
            creator_id=creator_id,
            sandbox_template_id=payload.sandbox_template_id,
            session_api_key=self._enc.encrypt_value(plaintext_key),
            session_api_key_hash=hash_session_api_key(plaintext_key),
            enabled=payload.enabled,
            sandbox_snapshot_id=payload.sandbox_snapshot_id,
            expires_at=payload.expires_at,
            snapshot_on_deactivate=snapshot_on_deactivate,
            meta=payload.meta,
        )
        if not self._perm_filter.matches(config):
            raise SandboxConfigPermissionScopeError(str(payload.sandbox_template_id))
        self._session.add(config)
        await self._session.flush()
        await self._session.refresh(config)
        return config

    async def get(self, config_id: uuid.UUID) -> SandboxConfig:
        """Retrieve a config by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(SandboxConfig).where(SandboxConfig.id == config_id)
        )
        result = await self._session.execute(stmt)
        config = result.scalar_one_or_none()
        if config is None:
            raise SandboxConfigNotFoundError(str(config_id))
        return config

    async def get_many(self, config_ids: list[uuid.UUID]) -> list[SandboxConfig | None]:
        """Retrieve configs by ids, positionally aligned with ``None`` for misses."""
        if not config_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SandboxConfig).where(SandboxConfig.id.in_(config_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, SandboxConfig] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(cid) for cid in config_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxConfigSearchFilter | None = None,
    ) -> tuple[list[SandboxConfig], uuid.UUID | None]:
        """Search configs ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(SandboxConfig).order_by(SandboxConfig.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SandboxConfig.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: SandboxConfigSearchFilter | None = None) -> int:
        """Count configs visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SandboxConfig))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        config_id: uuid.UUID,
        payload: SandboxConfigUpdate,
    ) -> SandboxConfig:
        """Partially update a sandbox config's mutable intent fields."""
        config = await self.get(config_id)
        fields = payload.model_fields_set
        if "enabled" in fields and payload.enabled is not None:
            config.enabled = payload.enabled
        if "sandbox_snapshot_id" in fields:
            config.sandbox_snapshot_id = payload.sandbox_snapshot_id
        if "snapshot_on_deactivate" in fields and payload.snapshot_on_deactivate is not None:
            config.snapshot_on_deactivate = payload.snapshot_on_deactivate
        if "expires_at" in fields:
            config.expires_at = payload.expires_at
        if "meta" in fields and payload.meta is not None:
            config.meta = payload.meta
        await self._session.flush()
        await self._session.refresh(config)
        return config

    async def delete(self, config_id: uuid.UUID) -> None:
        """Delete a sandbox config."""
        config = await self.get(config_id)
        await self._session.delete(config)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[SandboxConfigBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxConfig] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[SandboxConfig | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[SandboxConfig | None] = []
        for op in operations:
            if isinstance(op, SandboxConfigBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, SandboxConfigBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, SandboxConfigBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: SandboxConfigBatchCreate,
        perm_filters: dict[Action, SearchFilter[SandboxConfig] | None],
        *,
        creator_id: uuid.UUID,
    ) -> SandboxConfig:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await SandboxConfigService(self._session, filt, encryption_service=self._enc).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: SandboxConfigBatchUpdate,
        perm_filters: dict[Action, SearchFilter[SandboxConfig] | None],
    ) -> SandboxConfig:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await SandboxConfigService(self._session, filt, encryption_service=self._enc).update(
            op.id, op.data
        )

    async def _batch_delete(
        self,
        op: SandboxConfigBatchDelete,
        perm_filters: dict[Action, SearchFilter[SandboxConfig] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await SandboxConfigService(self._session, filt, encryption_service=self._enc).delete(op.id)
