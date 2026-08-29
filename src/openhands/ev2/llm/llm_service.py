"""Service layer for the LLM feature.

CRUD over :class:`StoredProviderConnection` and :class:`StoredLLM`, plus the
proxied completion action. Services contain business logic; the encryption
service is injected for tests. The ``api_key`` on a provider connection is
encrypted before persistence (JWE ciphertext, like ``OAuthClient.client_secret``)
and decrypted only when materializing the SDK :class:`ProviderConnection`.

The completion action resolves a stored LLM profile, materializes its SDK
:class:`LLM` (sourcing ``api_key``/``base_url``/``provider_connection_id`` from
the linked provider connection), and calls :meth:`LLM.acompletion`. The proxy
URL for an ``enable_proxy`` connection is built from :attr:`AppConfig.base_url`
plus the configured completion path.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.config import AppConfig, get_config
from openhands.ev2.encryption.encryption_service import EncryptionService, get_encryption_service
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection
from openhands.ev2.llm.llm_schemas import (
    LLMBatchCreate,
    LLMBatchDelete,
    LLMBatchOp,
    LLMBatchUpdate,
    LLMCreate,
    LLMSearchFilter,
    LLMUpdate,
    ProviderConnectionBatchCreate,
    ProviderConnectionBatchDelete,
    ProviderConnectionBatchOp,
    ProviderConnectionBatchUpdate,
    ProviderConnectionCreate,
    ProviderConnectionSearchFilter,
    ProviderConnectionUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL_SEARCH_FILTER, SearchFilter

if TYPE_CHECKING:
    from openhands.sdk.llm.llm import LLM

# ---------------------------------------------------------------------- #
# Errors
# ---------------------------------------------------------------------- #


class ProviderConnectionNotFoundError(Exception):
    """Raised when a provider connection id does not exist (or is out of scope)."""


class ProviderConnectionPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class LLMNotFoundError(Exception):
    """Raised when a stored LLM id does not exist (or is out of scope)."""


class LLMPermissionScopeError(Exception):
    """Raised when a create/update payload falls outside the principal's scope."""


class LLMConfigError(Exception):
    """Raised when a stored LLM config blob cannot materialize an SDK LLM."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


# ---------------------------------------------------------------------- #
# Proxy URL
# ---------------------------------------------------------------------- #


def proxy_url_for(connection_id: uuid.UUID, *, config: AppConfig | None = None) -> str:
    """Build the SDK ``base_url`` for an ``enable_proxy`` provider connection.

    Derived from :attr:`AppConfig.base_url` plus the configured completion path
    with the connection id appended, so LLM traffic is routed through this
    service's ``POST /llm/completion/{id}`` endpoint.
    """
    cfg = config or get_config()
    base = cfg.base_url.rstrip("/")
    path = cfg.llm.completion_path.strip("/")
    return f"{base}/{path}/{connection_id}"


# ---------------------------------------------------------------------- #
# Provider connection service
# ---------------------------------------------------------------------- #


class ProviderConnectionService:
    """CRUD over :class:`StoredProviderConnection`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[StoredProviderConnection] = ALL_SEARCH_FILTER,
        *,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()

    async def create(
        self, payload: ProviderConnectionCreate, *, user_id: uuid.UUID
    ) -> StoredProviderConnection:
        """Create a provider connection. The api_key is encrypted before persistence.

        Raises :class:`ProviderConnectionPermissionScopeError` if the row does
        not satisfy the principal's ``perm_filter``.
        """
        conn = StoredProviderConnection(
            user_id=user_id,
            display_name=payload.display_name,
            provider=payload.provider,
            api_key=self._enc.encrypt_value(payload.api_key) if payload.api_key else None,
            base_url=payload.base_url,
            enable_proxy=payload.enable_proxy,
        )
        if not self._perm_filter.matches(conn):
            raise ProviderConnectionPermissionScopeError(str(payload.display_name))
        self._session.add(conn)
        await self._session.flush()
        await self._session.refresh(conn)
        return conn

    async def get(self, connection_id: uuid.UUID) -> StoredProviderConnection:
        """Retrieve a provider connection by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(StoredProviderConnection).where(StoredProviderConnection.id == connection_id)
        )
        result = await self._session.execute(stmt)
        conn = result.scalar_one_or_none()
        if conn is None:
            raise ProviderConnectionNotFoundError(str(connection_id))
        return conn

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: ProviderConnectionSearchFilter | None = None,
    ) -> tuple[list[StoredProviderConnection], uuid.UUID | None]:
        """Search provider connections ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(
            select(StoredProviderConnection).order_by(StoredProviderConnection.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(StoredProviderConnection.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def update(
        self, connection_id: uuid.UUID, payload: ProviderConnectionUpdate
    ) -> StoredProviderConnection:
        """Partially update a provider connection."""
        conn = await self.get(connection_id)
        if payload.display_name is not None:
            conn.display_name = payload.display_name
        if payload.provider is not None:
            conn.provider = payload.provider
        if payload.api_key is not None:
            conn.api_key = self._enc.encrypt_value(payload.api_key)
        if payload.base_url is not None:
            conn.base_url = payload.base_url
        if payload.enable_proxy is not None:
            conn.enable_proxy = payload.enable_proxy
        await self._session.flush()
        await self._session.refresh(conn)
        return conn

    async def delete(self, connection_id: uuid.UUID) -> None:
        """Delete a provider connection. Cascades to its stored LLMs."""
        conn = await self.get(connection_id)
        await self._session.delete(conn)
        await self._session.flush()

    async def count(self, search_filter: ProviderConnectionSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(
            select(func.count()).select_from(StoredProviderConnection)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def get_many(
        self, connection_ids: list[uuid.UUID]
    ) -> list[StoredProviderConnection | None]:
        """Retrieve provider connections by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *connection_ids*: the i-th entry
        is the connection for ``connection_ids[i]`` or ``None`` when missing/out
        of scope. Duplicates are preserved. An empty list yields an empty result
        without hitting the DB.
        """
        if not connection_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(StoredProviderConnection).where(StoredProviderConnection.id.in_(connection_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, StoredProviderConnection] = {c.id: c for c in result.scalars().all()}
        return [by_id.get(cid) for cid in connection_ids]

    async def apply_batch(
        self,
        operations: list[ProviderConnectionBatchOp],
        perm_filters: dict[Action, SearchFilter[StoredProviderConnection] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[StoredProviderConnection | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the connection for create/update,
        ``None`` for delete.
        """
        results: list[StoredProviderConnection | None] = []
        for op in operations:
            if isinstance(op, ProviderConnectionBatchCreate):
                results.append(await self._batch_create(op, perm_filters, user_id=user_id))
            elif isinstance(op, ProviderConnectionBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, ProviderConnectionBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: ProviderConnectionBatchCreate,
        perm_filters: dict[Action, SearchFilter[StoredProviderConnection] | None],
        *,
        user_id: uuid.UUID,
    ) -> StoredProviderConnection:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await ProviderConnectionService(
            self._session, filt, encryption_service=self._enc
        ).create(op.data, user_id=user_id)

    async def _batch_update(
        self,
        op: ProviderConnectionBatchUpdate,
        perm_filters: dict[Action, SearchFilter[StoredProviderConnection] | None],
    ) -> StoredProviderConnection:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await ProviderConnectionService(
            self._session, filt, encryption_service=self._enc
        ).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: ProviderConnectionBatchDelete,
        perm_filters: dict[Action, SearchFilter[StoredProviderConnection] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await ProviderConnectionService(self._session, filt, encryption_service=self._enc).delete(
            op.id
        )


# ---------------------------------------------------------------------- #
# LLM service
# ---------------------------------------------------------------------- #


class LLMService:
    """CRUD over :class:`StoredLLM`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[StoredLLM] = ALL_SEARCH_FILTER,
        *,
        encryption_service: EncryptionService | None = None,
        config: AppConfig | None = None,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._enc = encryption_service or get_encryption_service()
        self._cfg = config or get_config()

    async def create(self, payload: LLMCreate, *, user_id: uuid.UUID) -> StoredLLM:
        """Create a stored LLM profile.

        Validates the provider connection exists and is in the principal's
        provider-connection scope, and that the config blob materializes an SDK
        :class:`LLM`. Raises :class:`LLMPermissionScopeError` on scope violation
        or :class:`LLMConfigError` on an invalid config blob.
        """
        # Ensure the referenced provider connection exists and is in scope.
        conn_stmt = select(StoredProviderConnection).where(
            StoredProviderConnection.id == payload.provider_connection_id,
            StoredProviderConnection.user_id == user_id,
        )
        conn = (await self._session.execute(conn_stmt)).scalar_one_or_none()
        if conn is None:
            raise LLMPermissionScopeError(str(payload.provider_connection_id))

        llm = StoredLLM(
            user_id=user_id,
            provider_connection_id=payload.provider_connection_id,
            model=payload.model,
            display_name=payload.display_name,
            config=payload.config,
        )
        if not self._perm_filter.matches(llm):
            raise LLMPermissionScopeError(str(payload.display_name))
        # Validate the config blob materializes an SDK LLM before persisting.
        try:
            llm.to_llm(conn.to_provider_connection(self._enc))
        except Exception as exc:
            raise LLMConfigError(str(exc)) from exc
        self._session.add(llm)
        await self._session.flush()
        await self._session.refresh(llm)
        return llm

    async def get(self, llm_id: uuid.UUID) -> StoredLLM:
        """Retrieve a stored LLM by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(select(StoredLLM).where(StoredLLM.id == llm_id))
        result = await self._session.execute(stmt)
        llm = result.scalar_one_or_none()
        if llm is None:
            raise LLMNotFoundError(str(llm_id))
        return llm

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: LLMSearchFilter | None = None,
    ) -> tuple[list[StoredLLM], uuid.UUID | None]:
        """Search stored LLMs ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(StoredLLM).order_by(StoredLLM.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(StoredLLM.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def update(self, llm_id: uuid.UUID, payload: LLMUpdate) -> StoredLLM:
        """Partially update a stored LLM. ``config`` replaces the blob wholesale."""
        llm = await self.get(llm_id)
        if payload.provider_connection_id is not None:
            # The new connection must exist and belong to the same owner.
            conn_stmt = select(StoredProviderConnection).where(
                StoredProviderConnection.id == payload.provider_connection_id,
                StoredProviderConnection.user_id == llm.user_id,
            )
            conn = (await self._session.execute(conn_stmt)).scalar_one_or_none()
            if conn is None:
                raise LLMPermissionScopeError(str(payload.provider_connection_id))
            llm.provider_connection_id = payload.provider_connection_id
        if payload.model is not None:
            llm.model = payload.model
        if payload.display_name is not None:
            llm.display_name = payload.display_name
        if payload.config is not None:
            llm.config = payload.config
        # Validate the merged config still materializes an SDK LLM.
        conn = await self._session.get(StoredProviderConnection, llm.provider_connection_id)
        if conn is None:
            raise LLMPermissionScopeError(str(llm.provider_connection_id))
        try:
            llm.to_llm(conn.to_provider_connection(self._enc))
        except Exception as exc:
            raise LLMConfigError(str(exc)) from exc
        await self._session.flush()
        await self._session.refresh(llm)
        return llm

    async def delete(self, llm_id: uuid.UUID) -> None:
        """Delete a stored LLM."""
        llm = await self.get(llm_id)
        await self._session.delete(llm)
        await self._session.flush()

    async def count(self, search_filter: LLMSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(StoredLLM))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def get_many(self, llm_ids: list[uuid.UUID]) -> list[StoredLLM | None]:
        """Retrieve stored LLMs by ids in a single query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *llm_ids*: the i-th entry is the
        LLM for ``llm_ids[i]`` or ``None`` when missing/out of scope. Duplicates
        are preserved. An empty list yields an empty result without hitting the DB.
        """
        if not llm_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(StoredLLM).where(StoredLLM.id.in_(llm_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, StoredLLM] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(lid) for lid in llm_ids]

    async def apply_batch(
        self,
        operations: list[LLMBatchOp],
        perm_filters: dict[Action, SearchFilter[StoredLLM] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[StoredLLM | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the LLM for create/update, ``None``
        for delete.
        """
        results: list[StoredLLM | None] = []
        for op in operations:
            if isinstance(op, LLMBatchCreate):
                results.append(await self._batch_create(op, perm_filters, user_id=user_id))
            elif isinstance(op, LLMBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, LLMBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: LLMBatchCreate,
        perm_filters: dict[Action, SearchFilter[StoredLLM] | None],
        *,
        user_id: uuid.UUID,
    ) -> StoredLLM:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await LLMService(
            self._session, filt, encryption_service=self._enc, config=self._cfg
        ).create(op.data, user_id=user_id)

    async def _batch_update(
        self,
        op: LLMBatchUpdate,
        perm_filters: dict[Action, SearchFilter[StoredLLM] | None],
    ) -> StoredLLM:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await LLMService(
            self._session, filt, encryption_service=self._enc, config=self._cfg
        ).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: LLMBatchDelete,
        perm_filters: dict[Action, SearchFilter[StoredLLM] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await LLMService(
            self._session, filt, encryption_service=self._enc, config=self._cfg
        ).delete(op.id)

    async def first_for_connection(
        self,
        connection_id: uuid.UUID,
        *,
        user_id: uuid.UUID,
    ) -> StoredLLM | None:
        """Return the first stored LLM owned by *user_id* pointing at *connection_id*."""
        stmt = (
            select(StoredLLM)
            .where(
                StoredLLM.provider_connection_id == connection_id,
                StoredLLM.user_id == user_id,
            )
            .order_by(StoredLLM.id)
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def materialize_llm(
        self,
        llm: StoredLLM,
        *,
        config: AppConfig | None = None,
    ) -> LLM:
        """Materialize the SDK :class:`LLM` for a stored profile.

        Resolves the linked provider connection (scoped to the profile owner),
        builds the SDK :class:`ProviderConnection` (with the proxy URL when
        ``enable_proxy`` is set), and returns ``llm.to_llm(connection)``.
        """
        cfg = config or self._cfg
        conn = await self._session.get(StoredProviderConnection, llm.provider_connection_id)
        if conn is None or conn.user_id != llm.user_id:
            raise LLMNotFoundError(str(llm.id))
        proxy = proxy_url_for(conn.id, config=cfg) if conn.enable_proxy else None
        sdk_conn = conn.to_provider_connection(self._enc, proxy_url=proxy)
        return llm.to_llm(sdk_conn)


__all__ = [
    "BatchPermissionDeniedError",
    "LLMConfigError",
    "LLMNotFoundError",
    "LLMPermissionScopeError",
    "LLMService",
    "ProviderConnectionNotFoundError",
    "ProviderConnectionPermissionScopeError",
    "ProviderConnectionService",
    "proxy_url_for",
]
