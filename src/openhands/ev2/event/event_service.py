"""Service layer for the event feature.

Pure logic (truncation, envelope format, derivable storage keys) lives in
module-level helpers; I/O is isolated at the edges per AGENTS.md §4. The
service holds the effective ``perm_filter`` (scoping read/search SQL to the
principal's visible conversations) plus the backing-store handle and body
cap. Writes store the body-then-flush row; a store failure is logged and
swallowed so the Postgres row still goes in (the failure/degradation mode
agreed in the parent issue). The reconciliation/backfill job rebuilds rows
from the store.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.event.event_models import Event
from openhands.ev2.event.event_schemas import EventCreate, EventSearchFilter
from openhands.ev2.event.event_store import EventBodyStore
from openhands.ev2.util.search_filter import ALL, SearchFilter

logger = logging.getLogger(__name__)

_TRUNCATED_MARKER = "_truncated"
_PREVIEW_BYTES = 4096


class EventNotFoundError(Exception):
    """Raised when an event id does not exist (or is out of scope)."""


class ConversationNotFoundError(Exception):
    """Raised when the parent conversation id does not exist."""


class EventPermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class EventBodyNotFoundError(Exception):
    """Raised when a truncated event's stored body is absent from the store."""


def _stub_or_payload(serialized: bytes, payload: dict[str, Any], cap: int) -> dict[str, Any]:
    """Return the payload itself, or a self-describing truncation stub.

    The stub is stored at write time so the row is honest and queryable
    (``body->>'_truncated' = 'true'``), not synthesized on read.
    """
    if len(serialized) <= cap:
        return payload
    preview = serialized[:_PREVIEW_BYTES].decode("utf-8", errors="replace")
    return {
        _TRUNCATED_MARKER: True,
        "original_size_bytes": len(serialized),
        "preview": preview,
    }


def _serialize(payload: dict[str, Any]) -> bytes:
    """Serialize a payload deterministically for size accounting."""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _envelope_payload(event: Event, full_body: dict[str, Any]) -> bytes:
    """The self-describing stored envelope for an event row.

    Carries the *full* payload, never the truncation stub — the row body may
    be stubbed while the store must always hold the original body.
    """
    envelope = {
        "id": str(event.id),
        "conversation_id": str(event.conversation_id),
        "kind": event.kind,
        "timestamp": event.timestamp.isoformat(),
        "size_bytes": event.size_bytes,
        "body": full_body,
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def _event_from_envelope(
    envelope: dict[str, Any],
    *,
    event_id: uuid.UUID,
    event_date: date,
    body_cap_bytes: int,
) -> Event:
    """Rebuild an :class:`Event` row from a stored envelope (backfill path).

    Over-cap payloads are re-stubbed; the row is stamped with the stored id
    and timestamp rather than the server defaults. The date comes from the
    object key when the envelope lacks a timestamp.
    """
    body = envelope.get("body")
    if not isinstance(body, dict):
        body = {}
    serialized = _serialize(body)
    timestamp_raw = envelope.get("timestamp")
    if isinstance(timestamp_raw, str):
        timestamp = datetime.fromisoformat(timestamp_raw).astimezone(UTC)
    else:
        timestamp = datetime(event_date.year, event_date.month, event_date.day, tzinfo=UTC)
    event = Event(
        conversation_id=uuid.UUID(str(envelope.get("conversation_id"))),
        kind=str(envelope.get("kind", "backfill")),
        body=_stub_or_payload(serialized, body, body_cap_bytes),
        size_bytes=len(serialized),
    )
    # id/timestamp are init=False on the model; stamp them after construction.
    event.id = event_id
    event.timestamp = timestamp
    return event


def _partition_name(day: datetime) -> str:
    """The daily partition table name for *day* (a UTC date)."""
    return f"events_{day.strftime('%Y%m%d')}"


def _day_bounds(day: datetime) -> tuple[str, str]:
    """The ``[from, to)`` DATE bounds for the *day* partition (ISO strings)."""
    start = day.date().isoformat()
    end = (day + timedelta(days=1)).date().isoformat()
    return start, end


class EventService:
    """CRUD (create/read) over events, plus partition management and backfill."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Event] = ALL,
        store: EventBodyStore | None = None,
        body_cap_bytes: int = 262_144,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter
        self._store = store
        self._body_cap_bytes = body_cap_bytes

    async def create(self, conversation_id: uuid.UUID, payload: EventCreate) -> Event:
        """Persist an event under a conversation.

        Stores the full body to the backing store (best-effort), then flushes
        the row — either the inline payload or the truncation stub — so a
        store outage never blocks the row.
        """
        if not await self._conversation_exists(conversation_id):
            raise ConversationNotFoundError(str(conversation_id))
        serialized = _serialize(payload.body)
        event = Event(
            conversation_id=conversation_id,
            kind=payload.kind,
            body=_stub_or_payload(serialized, payload.body, self._body_cap_bytes),
            size_bytes=len(serialized),
        )
        if not self._perm_filter.matches(event):
            raise EventPermissionScopeError(str(conversation_id))
        self._session.add(event)
        await self._session.flush()
        await self._session.refresh(event)
        if self._store is not None:
            try:
                envelope = _envelope_payload(event, payload.body)
                self._store.store_body(event.id, event.timestamp.date(), envelope)
            except Exception:
                # Failure mode: store down → the row is still committed; the
                # full body is lost unless the ingestion path retries.
                logger.exception("failed to store full event body %s", event.id)
        return event

    async def get(self, conversation_id: uuid.UUID, event_id: uuid.UUID) -> Event:
        """Retrieve an event by id, scoped by ``perm_filter`` and parent."""
        stmt = self._perm_filter.filter_sql(
            select(Event).where(
                Event.id == event_id,
                Event.conversation_id == conversation_id,
            )
        )
        result = await self._session.execute(stmt)
        event = result.scalar_one_or_none()
        if event is None:
            raise EventNotFoundError(str(event_id))
        return event

    async def search_events(
        self,
        conversation_id: uuid.UUID,
        *,
        cursor: tuple[datetime, uuid.UUID] | None = None,
        limit: int = 50,
        search_filter: EventSearchFilter | None = None,
    ) -> tuple[list[Event], tuple[datetime, uuid.UUID] | None]:
        """Search events of one conversation, ordered by ``(timestamp, id)``.

        Keyed pagination via an optional ``(timestamp, id)`` cursor. Returns
        (events, next_cursor); next_cursor is None when exhausted.
        """
        stmt = self._perm_filter.filter_sql(
            select(Event)
            .where(Event.conversation_id == conversation_id)
            .order_by(Event.timestamp, Event.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            ts, eid = cursor
            stmt = stmt.where(
                or_(
                    Event.timestamp > ts,
                    (Event.timestamp == ts) & (Event.id > eid),
                )
            )
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        events = list(result.scalars().all())
        next_cursor = (events[-1].timestamp, events[-1].id) if len(events) == limit else None
        return events, next_cursor

    async def get_body(self, conversation_id: uuid.UUID, event_id: uuid.UUID) -> bytes:
        """Return the event's full body as serialized JSON.

        Not-truncated events serve their row payload directly; truncated ones
        resolve via the derivable storage key. Raises
        :class:`EventBodyNotFoundError` when the backing store lacks the
        object (or no store is configured).
        """
        event = await self.get(conversation_id, event_id)
        if not event.body.get(_TRUNCATED_MARKER):
            return _serialize(event.body)
        if self._store is None:
            raise EventBodyNotFoundError(str(event_id))
        stored = self._store.load_body(event_id, event.timestamp.date())
        if stored is None:
            raise EventBodyNotFoundError(str(event_id))
        try:
            envelope = json.loads(stored)
        except ValueError as exc:
            raise EventBodyNotFoundError(str(event_id)) from exc
        body = envelope.get("body")
        if not isinstance(body, dict):
            raise EventBodyNotFoundError(str(event_id))
        return _serialize(body)

    # ------------------------------------------------------------------ #
    # Partition management (mirrors LlmUsageService)
    # ------------------------------------------------------------------ #

    async def ensure_partitions(
        self,
        *,
        preallocate_days: int,
        retention_days: int,
        now: datetime | None = None,
    ) -> tuple[list[str], list[str]]:
        """Allocate future daily partitions and drop expired ones.

        Returns ``(created, dropped)``. Idempotent; ensures a ``DEFAULT``
        partition so inserts never fail before the first sweep. When a
        partition is dropped, the backing-store cleanup for the same date
        prefix runs here (aligned single sweep) — the caller's ``store``
        handles the day-prefix delete.
        """
        now = now or datetime.now(UTC)
        created: list[str] = []
        for offset in range(preallocate_days):
            day = (now + timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            name = await self._ensure_partition(day)
            if name is not None:
                created.append(name)
        await self._session.execute(
            text("CREATE TABLE IF NOT EXISTS events_default PARTITION OF events DEFAULT")
        )
        dropped = await self._drop_expired_partitions(retention_days, now)
        await self._session.commit()
        if dropped and self._store is not None:
            for name in dropped:
                self._delete_store_prefix(name)
        return created, dropped

    def _delete_store_prefix(self, partition_name: str) -> None:
        """Aligned store cleanup for one dropped daily partition."""
        suffix = partition_name.rsplit("_", 1)[-1]
        day = datetime.strptime(suffix, "%Y%m%d").date()
        try:
            removed = self._store.delete_day(day) if self._store is not None else 0
            logger.info(
                "deleted %d stored bodies for dropped partition %s", removed, partition_name
            )
        except Exception:
            logger.exception("store cleanup failed for dropped partition %s", partition_name)

    async def _ensure_partition(self, day: datetime) -> str | None:
        """Create the daily partition for *day* if absent; return its name or None."""
        name = _partition_name(day)
        start, end = _day_bounds(day)
        exists = (
            await self._session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = :n"), {"n": name}
            )
        ).scalar_one_or_none()
        if exists is not None:
            return None
        await self._session.execute(
            text(
                f"CREATE TABLE {name} PARTITION OF events FOR VALUES FROM ('{start}') TO ('{end}')"
            )
        )
        return name

    async def _drop_expired_partitions(self, retention_days: int, now: datetime) -> list[str]:
        """Drop partitions older than ``retention_days``. Never drops DEFAULT."""
        cutoff = (now - timedelta(days=retention_days)).date()
        rows = (
            await self._session.execute(
                text(
                    "SELECT inhrelid::regclass::text AS name FROM pg_inherits "
                    "WHERE inhparent = 'events'::regclass "
                    "AND inhrelid::regclass::text LIKE 'events_%'"
                )
            )
        ).all()
        dropped: list[str] = []
        for row in rows:
            name = row[0]
            suffix = name.rsplit("_", 1)[-1] if "_" in name else ""
            try:
                day = datetime.strptime(suffix, "%Y%m%d").date()
            except ValueError:
                continue  # not a dated partition
            if day < cutoff:
                await self._session.execute(text(f"DROP TABLE IF EXISTS {name}"))
                dropped.append(name)
        return dropped

    # ------------------------------------------------------------------ #
    # Reconciliation / backfill (store → Postgres)
    # ------------------------------------------------------------------ #

    async def backfill(self) -> int:
        """Restore rows for stored envelopes missing from ``events``.

        Covers the Postgres-down failure mode: the ingestion path wrote the
        envelope to the backing store but the row never landed. Every stored
        object is re-parsed and inserted with its stored id/timestamp. Id,
        timestamp and conversation linkage come from the self-describing
        envelope.
        """
        if self._store is None:
            return 0
        restored = 0
        for event_id, event_date, payload in self._store.iter_envelopes():
            existing = (
                await self._session.execute(select(Event.id).where(Event.id == event_id))
            ).scalar_one_or_none()
            if existing is not None:
                continue
            try:
                envelope = json.loads(payload)
            except ValueError:
                continue
            if not isinstance(envelope, dict):
                continue
            event = _event_from_envelope(
                envelope,
                event_id=event_id,
                event_date=event_date,
                body_cap_bytes=self._body_cap_bytes,
            )
            self._session.add(event)
            await self._session.flush()
            restored += 1
        await self._session.commit()
        return restored

    async def _conversation_exists(self, conversation_id: uuid.UUID) -> bool:
        """Unscoped existence check for the parent conversation on create."""
        result = await self._session.execute(
            select(Conversation.id).where(Conversation.id == conversation_id)
        )
        return result.scalar_one_or_none() is not None
