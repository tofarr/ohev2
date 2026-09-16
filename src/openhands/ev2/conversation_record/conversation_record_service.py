"""Service layer for the conversation_record feature.

Services contain business logic; repositories contain data access. This module
exposes a thin ``ConversationRecordService`` over SQLAlchemy async sessions per
AGENTS.md §4. The service holds the effective ``perm_filter`` (the search
filter from the centralized permission checker) as a field, set at
construction, that scopes the SQL to rows the principal is allowed to
see/modify; :meth:`create` validates the incoming item against it in memory
(AGENTS.md §9 — authorization enforced in services, not just routers).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.conversation_record.conversation_record_models import ConversationRecord
from openhands.ev2.conversation_record.conversation_record_schemas import (
    ConversationRecordBatchCreate,
    ConversationRecordBatchDelete,
    ConversationRecordBatchOp,
    ConversationRecordBatchUpdate,
    ConversationRecordCreate,
    ConversationRecordSearchFilter,
    ConversationRecordUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

# Fields a PATCH may set on a ConversationRecord. ``sandbox_config_id`` is immutable.
_UPDATE_FIELDS: tuple[str, ...] = (
    "title",
    "llm_model",
    "agent_kind",
    "selected_repository",
    "selected_branch",
    "trigger",
    "accumulated_cost",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "event_callbacks",
)


class ConversationRecordNotFoundError(Exception):
    """Raised when a conversation_record id does not exist."""


class ConversationRecordPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class ConversationRecordService:
    """CRUD operations over conversation_records.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[ConversationRecord] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: ConversationRecordCreate) -> ConversationRecord:
        """Persist a conversation_record.

        Raises :class:`ConversationRecordPermissionScopeError` if the prospective row
        does not satisfy the service's ``perm_filter`` (the principal's create
        scope).
        """
        conversation_record = ConversationRecord(
            title=payload.title,
            sandbox_config_id=payload.sandbox_config_id,
            llm_model=payload.llm_model,
            agent_kind=payload.agent_kind,
            selected_repository=payload.selected_repository,
            selected_branch=payload.selected_branch,
            trigger=payload.trigger,
            event_callbacks=payload.event_callbacks,
        )
        if not self._perm_filter.matches(conversation_record):
            raise ConversationRecordPermissionScopeError(str(payload.sandbox_config_id))
        self._session.add(conversation_record)
        await self._session.flush()
        await self._session.refresh(conversation_record)
        return conversation_record

    async def get(self, conversation_record_id: uuid.UUID) -> ConversationRecord:
        """Retrieve a conversation_record by id, scoped by ``perm_filter``.

        Raises :class:`ConversationRecordNotFoundError` if the conversation_record is
        missing or out of the principal's scope (so callers return 404 without
        leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(ConversationRecord).where(ConversationRecord.id == conversation_record_id)
        )
        result = await self._session.execute(stmt)
        conversation_record = result.scalar_one_or_none()
        if conversation_record is None:
            raise ConversationRecordNotFoundError(str(conversation_record_id))
        return conversation_record

    async def get_many(
        self,
        conversation_record_ids: list[uuid.UUID],
    ) -> list[ConversationRecord | None]:
        """Retrieve conversation_records by ids in one query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *conversation_record_ids*: the i-th
        entry is the :class:`ConversationRecord` for ``conversation_record_ids[i]`` or
        ``None`` when missing/out of scope. Duplicate ids are preserved. An
        empty *conversation_record_ids* yields an empty list without hitting the DB.
        """
        if not conversation_record_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(ConversationRecord).where(ConversationRecord.id.in_(conversation_record_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, ConversationRecord] = {c.id: c for c in result.scalars().all()}
        return [by_id.get(cid) for cid in conversation_record_ids]

    async def search_conversation_records(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: ConversationRecordSearchFilter | None = None,
    ) -> tuple[list[ConversationRecord], uuid.UUID | None]:
        """Search conversation_records ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (conversation_records, next_cursor). next_cursor is None when
        exhausted.
        """
        stmt = self._perm_filter.filter_sql(
            select(ConversationRecord).order_by(ConversationRecord.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(ConversationRecord.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        conversation_records = list(result.scalars().all())
        next_cursor = conversation_records[-1].id if len(conversation_records) == limit else None
        return conversation_records, next_cursor

    async def update(
        self, conversation_record_id: uuid.UUID, payload: ConversationRecordUpdate
    ) -> ConversationRecord:
        """Partially update a conversation_record. Raises on missing/scoped-out id."""
        conversation_record = await self.get(conversation_record_id)
        for field in _UPDATE_FIELDS:
            value = getattr(payload, field)
            if value is not None:
                setattr(conversation_record, field, value)
        await self._session.flush()
        await self._session.refresh(conversation_record)
        return conversation_record

    async def delete(self, conversation_record_id: uuid.UUID) -> None:
        """Delete a conversation_record. Raises if missing or out of scope."""
        conversation_record = await self.get(conversation_record_id)
        await self._session.delete(conversation_record)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[ConversationRecordBatchOp],
        perm_filters: dict[Action, SearchFilter[ConversationRecord] | None],
    ) -> list[ConversationRecord | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the conversation_record for create/update,
        ``None`` for delete.
        """
        results: list[ConversationRecord | None] = []
        for op in operations:
            if isinstance(op, ConversationRecordBatchCreate):
                results.append(await self._batch_create(op, perm_filters))
            elif isinstance(op, ConversationRecordBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, ConversationRecordBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: ConversationRecordBatchCreate,
        perm_filters: dict[Action, SearchFilter[ConversationRecord] | None],
    ) -> ConversationRecord:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        # A per-operation ConversationRecordService so the create's perm_filter
        # matches the operation's action, not the batch endpoint's scope.
        return await ConversationRecordService(self._session, filt).create(op.data)

    async def _batch_update(
        self,
        op: ConversationRecordBatchUpdate,
        perm_filters: dict[Action, SearchFilter[ConversationRecord] | None],
    ) -> ConversationRecord:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await ConversationRecordService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: ConversationRecordBatchDelete,
        perm_filters: dict[Action, SearchFilter[ConversationRecord] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await ConversationRecordService(self._session, filt).delete(op.id)

    async def count(
        self,
        search_filter: ConversationRecordSearchFilter | None = None,
    ) -> int:
        """Total conversation_record count, scoped by the service's ``perm_filter`` and
        the optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(ConversationRecord))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())
