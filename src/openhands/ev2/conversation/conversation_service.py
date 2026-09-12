"""Service layer for the conversation feature.

Services contain business logic; repositories contain data access. This module
exposes a thin ``ConversationService`` over SQLAlchemy async sessions per
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

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import (
    ConversationBatchCreate,
    ConversationBatchDelete,
    ConversationBatchOp,
    ConversationBatchUpdate,
    ConversationCreate,
    ConversationSearchFilter,
    ConversationUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

# Fields a PATCH may set on a Conversation. ``sandbox_config_id`` is immutable.
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
)


class ConversationNotFoundError(Exception):
    """Raised when a conversation id does not exist."""


class ConversationPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class ConversationService:
    """CRUD operations over conversations.

    The service is constructed per request with the request-scoped session and
    the principal's effective ``perm_filter``; it holds no other mutable state.
    """

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Conversation] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(self, payload: ConversationCreate) -> Conversation:
        """Persist a conversation.

        Raises :class:`ConversationPermissionScopeError` if the prospective row
        does not satisfy the service's ``perm_filter`` (the principal's create
        scope).
        """
        conversation = Conversation(
            title=payload.title,
            sandbox_config_id=payload.sandbox_config_id,
            llm_model=payload.llm_model,
            agent_kind=payload.agent_kind,
            selected_repository=payload.selected_repository,
            selected_branch=payload.selected_branch,
            trigger=payload.trigger,
        )
        if not self._perm_filter.matches(conversation):
            raise ConversationPermissionScopeError(str(payload.sandbox_config_id))
        self._session.add(conversation)
        await self._session.flush()
        await self._session.refresh(conversation)
        return conversation

    async def get(self, conversation_id: uuid.UUID) -> Conversation:
        """Retrieve a conversation by id, scoped by ``perm_filter``.

        Raises :class:`ConversationNotFoundError` if the conversation is
        missing or out of the principal's scope (so callers return 404 without
        leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(Conversation).where(Conversation.id == conversation_id)
        )
        result = await self._session.execute(stmt)
        conversation = result.scalar_one_or_none()
        if conversation is None:
            raise ConversationNotFoundError(str(conversation_id))
        return conversation

    async def get_many(
        self,
        conversation_ids: list[uuid.UUID],
    ) -> list[Conversation | None]:
        """Retrieve conversations by ids in one query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *conversation_ids*: the i-th
        entry is the :class:`Conversation` for ``conversation_ids[i]`` or
        ``None`` when missing/out of scope. Duplicate ids are preserved. An
        empty *conversation_ids* yields an empty list without hitting the DB.
        """
        if not conversation_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(Conversation).where(Conversation.id.in_(conversation_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, Conversation] = {c.id: c for c in result.scalars().all()}
        return [by_id.get(cid) for cid in conversation_ids]

    async def search_conversations(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: ConversationSearchFilter | None = None,
    ) -> tuple[list[Conversation], uuid.UUID | None]:
        """Search conversations ordered by id, keyed-pagination via cursor.

        The service's ``perm_filter`` scopes the SQL to rows the principal may
        see; the optional *search_filter* (from query params) is ANDed on top.
        Returns (conversations, next_cursor). next_cursor is None when
        exhausted.
        """
        stmt = self._perm_filter.filter_sql(select(Conversation).order_by(Conversation.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Conversation.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        conversations = list(result.scalars().all())
        next_cursor = conversations[-1].id if len(conversations) == limit else None
        return conversations, next_cursor

    async def update(self, conversation_id: uuid.UUID, payload: ConversationUpdate) -> Conversation:
        """Partially update a conversation. Raises on missing/scoped-out id."""
        conversation = await self.get(conversation_id)
        for field in _UPDATE_FIELDS:
            value = getattr(payload, field)
            if value is not None:
                setattr(conversation, field, value)
        await self._session.flush()
        await self._session.refresh(conversation)
        return conversation

    async def delete(self, conversation_id: uuid.UUID) -> None:
        """Delete a conversation. Raises if missing or out of scope."""
        conversation = await self.get(conversation_id)
        await self._session.delete(conversation)
        await self._session.flush()

    async def apply_batch(
        self,
        operations: list[ConversationBatchOp],
        perm_filters: dict[Action, SearchFilter[Conversation] | None],
    ) -> list[Conversation | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the conversation for create/update,
        ``None`` for delete.
        """
        results: list[Conversation | None] = []
        for op in operations:
            if isinstance(op, ConversationBatchCreate):
                results.append(await self._batch_create(op, perm_filters))
            elif isinstance(op, ConversationBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, ConversationBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: ConversationBatchCreate,
        perm_filters: dict[Action, SearchFilter[Conversation] | None],
    ) -> Conversation:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        # A per-operation ConversationService so the create's perm_filter
        # matches the operation's action, not the batch endpoint's scope.
        return await ConversationService(self._session, filt).create(op.data)

    async def _batch_update(
        self,
        op: ConversationBatchUpdate,
        perm_filters: dict[Action, SearchFilter[Conversation] | None],
    ) -> Conversation:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await ConversationService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: ConversationBatchDelete,
        perm_filters: dict[Action, SearchFilter[Conversation] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await ConversationService(self._session, filt).delete(op.id)

    async def count(
        self,
        search_filter: ConversationSearchFilter | None = None,
    ) -> int:
        """Total conversation count, scoped by the service's ``perm_filter`` and
        the optional *search_filter* (the same query-param filter the collection
        endpoint accepts)."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Conversation))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())
