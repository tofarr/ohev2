"""Service layer for the event callback feature.

CRUD over :class:`EventCallback`. Services contain business logic; the
service holds the effective ``perm_filter`` (from the centralized permission
checker) as a field, set at construction, that scopes the SQL to rows the
principal is allowed to see/modify; :meth:`create` validates the incoming item
against it in memory (AGENTS.md §9 — authorization enforced in services, not
just routers).

The exactly-one-link invariant (exactly one of ``conversation_id`` /
``conversation_template_id`` is set) is enforced by the schemas on create and
re-validated against the merged row on update. The DB CHECK constraint is the
backstop.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.event_callback.event_callback_models import EventCallback
from openhands.ev2.event_callback.event_callback_schemas import (
    EventCallbackBatchCreate,
    EventCallbackBatchDelete,
    EventCallbackBatchOp,
    EventCallbackBatchUpdate,
    EventCallbackCreate,
    EventCallbackSearchFilter,
    EventCallbackUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


def _identity(value: Any) -> Any:
    return value


_UPDATE_TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "event_kind": _identity,
    "processor": _identity,
    "status": _identity,
    "detail": _identity,
    "last_event_id": _identity,
    "last_run_at": _identity,
}


class EventCallbackNotFoundError(Exception):
    """Raised when an event callback id does not exist (or is out of scope)."""


class EventCallbackPermissionScopeError(Exception):
    """Raised when a create/update payload falls outside the principal's scope."""


class EventCallbackLinkInvariantError(Exception):
    """Raised when an update would violate the exactly-one-link invariant."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class EventCallbackService:
    """CRUD over :class:`EventCallback`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[EventCallback] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: EventCallbackCreate,
        *,
        creator_id: uuid.UUID,
    ) -> EventCallback:
        """Persist an event callback.

        Raises :class:`EventCallbackPermissionScopeError` if the prospective
        row does not satisfy the service's ``perm_filter``. The exactly-one-link
        invariant is validated by the schema before reaching here.
        """
        callback = EventCallback(
            creator_id=creator_id,
            event_kind=payload.event_kind,
            processor=payload.processor,
            conversation_id=payload.conversation_id,
            conversation_template_id=payload.conversation_template_id,
        )
        if not self._perm_filter.matches(callback):
            raise EventCallbackPermissionScopeError(payload.event_kind)
        self._session.add(callback)
        await self._session.flush()
        await self._session.refresh(callback)
        return callback

    async def get(self, callback_id: uuid.UUID) -> EventCallback:
        """Retrieve a callback by id, scoped by ``perm_filter``.

        Raises :class:`EventCallbackNotFoundError` if the callback is missing or
        out of the principal's scope (so callers return 404 without leaking
        existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(EventCallback).where(EventCallback.id == callback_id)
        )
        result = await self._session.execute(stmt)
        callback = result.scalar_one_or_none()
        if callback is None:
            raise EventCallbackNotFoundError(str(callback_id))
        return callback

    async def get_many(
        self,
        callback_ids: list[uuid.UUID],
    ) -> list[EventCallback | None]:
        """Retrieve callbacks by ids in one query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *callback_ids*: the i-th entry
        is the :class:`EventCallback` for ``callback_ids[i]`` or ``None`` when
        missing/out of scope. Duplicate ids are preserved. An empty list yields
        an empty result without hitting the DB.
        """
        if not callback_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(EventCallback).where(EventCallback.id.in_(callback_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, EventCallback] = {c.id: c for c in result.scalars().all()}
        return [by_id.get(cid) for cid in callback_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: EventCallbackSearchFilter | None = None,
    ) -> tuple[list[EventCallback], uuid.UUID | None]:
        """Search callbacks ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(EventCallback).order_by(EventCallback.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(EventCallback.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def update(
        self,
        callback_id: uuid.UUID,
        payload: EventCallbackUpdate,
    ) -> EventCallback:
        """Partially update an event callback.

        The link fields (``conversation_id`` / ``conversation_template_id``) may
        be changed, but the exactly-one invariant is re-validated against the
        merged row. A ``None`` link field explicitly clears it.
        """
        callback = await self.get(callback_id)
        fields = payload.model_fields_set
        self._apply_update(callback, payload, fields)
        self._enforce_link_invariant(callback, fields)
        await self._session.flush()
        await self._session.refresh(callback)
        return callback

    @staticmethod
    def _apply_update(
        callback: EventCallback,
        payload: EventCallbackUpdate,
        fields: set[str],
    ) -> None:
        """Map a partial update onto an existing row.

        Link fields and the merged-result state fields are all explicitly
        settable (clearing to ``None`` is meaningful for the nullable ones).
        """
        for field, transform in _UPDATE_TRANSFORMS.items():
            if field in fields:
                setattr(callback, field, transform(getattr(payload, field)))
        if "conversation_id" in fields:
            callback.conversation_id = payload.conversation_id
        if "conversation_template_id" in fields:
            callback.conversation_template_id = payload.conversation_template_id

    @staticmethod
    def _enforce_link_invariant(
        callback: EventCallback,
        fields: set[str],
    ) -> None:
        """Re-validate the exactly-one-link invariant on the merged row.

        The schema rejects both-links-set, but an update that flips only one
        link field against a row whose other link is set could produce a row
        with both set — this catches that case at the service layer (the DB
        CHECK constraint is the backstop).
        """
        if (callback.conversation_id is None) == (callback.conversation_template_id is None):
            raise EventCallbackLinkInvariantError(
                "Exactly one of conversation_id / conversation_template_id must be set."
            )

    async def delete(self, callback_id: uuid.UUID) -> None:
        """Delete an event callback."""
        callback = await self.get(callback_id)
        await self._session.delete(callback)
        await self._session.flush()

    async def count(
        self,
        search_filter: EventCallbackSearchFilter | None = None,
    ) -> int:
        """Total callback count, scoped by the service's ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(EventCallback))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[EventCallbackBatchOp],
        perm_filters: dict[Action, SearchFilter[EventCallback] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[EventCallback | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the callback for create/update,
        ``None`` for delete.
        """
        results: list[EventCallback | None] = []
        for op in operations:
            if isinstance(op, EventCallbackBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, EventCallbackBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, EventCallbackBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: EventCallbackBatchCreate,
        perm_filters: dict[Action, SearchFilter[EventCallback] | None],
        *,
        creator_id: uuid.UUID,
    ) -> EventCallback:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await EventCallbackService(self._session, filt).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: EventCallbackBatchUpdate,
        perm_filters: dict[Action, SearchFilter[EventCallback] | None],
    ) -> EventCallback:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await EventCallbackService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: EventCallbackBatchDelete,
        perm_filters: dict[Action, SearchFilter[EventCallback] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await EventCallbackService(self._session, filt).delete(op.id)
