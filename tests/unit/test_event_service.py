"""Unit tests for the event service (DB-backed projection + body store)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal, make_sandbox_config

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import ConversationCreate
from openhands.ev2.conversation.conversation_service import ConversationService
from openhands.ev2.event.event_models import Event
from openhands.ev2.event.event_schemas import EventCreate, EventSearchFilter
from openhands.ev2.event.event_security import EventAccessFilter
from openhands.ev2.event.event_service import (
    ConversationNotFoundError,
    EventBodyNotFoundError,
    EventNotFoundError,
    EventPermissionScopeError,
    EventService,
)
from openhands.ev2.event.event_store import EventBodyStore, FilesystemEventBodyStore
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL

_CAP = 1024


def _payload(**overrides: Any) -> EventCreate:
    data: dict[str, Any] = {"kind": "message", "body": {"text": "hello"}}
    data.update(overrides)
    return EventCreate(**data)


class _BrokenStore(EventBodyStore):
    """A store whose writes fail — simulates the store-down mode."""

    def __init__(self) -> None:
        super().__init__("")

    def store_body(self, event_id: uuid.UUID, event_date: Any, payload: bytes) -> None:
        raise RuntimeError("store down")

    def load_body(self, event_id: uuid.UUID, event_date: Any) -> bytes | None:
        raise RuntimeError("store down")

    def delete_day(self, event_date: Any) -> int:
        raise RuntimeError("store down")

    def iter_envelopes(self) -> Any:
        raise RuntimeError("store down")


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="owner@example.com", username="owner")


@pytest.fixture
async def sandbox_config(session: AsyncSession, owner: User) -> SandboxConfig:
    return await make_sandbox_config(session, creator_id=owner.id)


@pytest.fixture
async def conversation(session: AsyncSession, sandbox_config: SandboxConfig) -> Conversation:
    """Create a real parent conversation for the event fixture wiring."""
    convo_service = ConversationService(session, ALL)
    payload = ConversationCreate(
        title="parent",
        sandbox_config_id=sandbox_config.id,
        llm_model="claude-sonnet-4",
        agent_kind="openhands",
        selected_repository=None,
        selected_branch=None,
        trigger="manual",
    )
    return await convo_service.create(payload)


class TestCreateEvent:
    async def test_create_inline_body_sized(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, body_cap_bytes=_CAP)
        event = await service.create(conversation.id, _payload())
        assert event.id is not None
        assert event.kind == "message"
        assert event.body == {"text": "hello"}
        serialized = json.dumps({"text": "hello"}, separators=(",", ":")).encode()
        assert event.size_bytes == len(serialized)
        assert event.timestamp is not None

    async def test_create_over_cap_stores_stub(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, body_cap_bytes=_CAP)
        big = {"text": "x" * (_CAP * 2)}
        event = await service.create(conversation.id, _payload(body=big))
        stub = event.body
        assert stub["_truncated"] is True
        assert stub["original_size_bytes"] == event.size_bytes
        assert isinstance(stub["preview"], str)
        assert event.size_bytes > _CAP

    async def test_create_unknown_conversation_raises(self, session: AsyncSession) -> None:
        service = EventService(session, ALL)
        with pytest.raises(ConversationNotFoundError):
            await service.create(uuid.uuid4(), _payload())

    async def test_create_outside_scope_denied(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        # EventAccessFilter keyed on another user cannot match: the prospective
        # row's conversation relationship is empty, so the in-memory check
        # fails closed.
        scoped = EventService(session, EventAccessFilter[Event](user_id=uuid.uuid4()))
        with pytest.raises(EventPermissionScopeError):
            await scoped.create(conversation.id, _payload())

    async def test_store_failure_is_best_effort(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, store=_BrokenStore())
        event = await service.create(conversation.id, _payload())
        assert event.id is not None

    async def test_every_event_body_lands_in_store(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store, body_cap_bytes=_CAP)
        event = await service.create(conversation.id, _payload())
        envelope_bytes = store.load_body(event.id, event.timestamp.date())
        assert envelope_bytes is not None
        envelope = json.loads(envelope_bytes)
        assert envelope["id"] == str(event.id)
        assert envelope["conversation_id"] == str(event.conversation_id)
        assert envelope["kind"] == event.kind
        assert envelope["body"] == event.body


class TestGetEvent:
    async def test_get_existing(self, session: AsyncSession, conversation: Conversation) -> None:
        service = EventService(session, ALL)
        created = await service.create(conversation.id, _payload())
        fetched = await service.get(conversation.id, created.id)
        assert fetched.id == created.id

    async def test_get_missing_raises(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        with pytest.raises(EventNotFoundError):
            await service.get(conversation.id, uuid.uuid4())

    async def test_get_out_of_scope_raises(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        created = await service.create(conversation.id, _payload())
        stranger = EventService(session, EventAccessFilter[Event](user_id=uuid.uuid4()))
        with pytest.raises(EventNotFoundError):
            await stranger.get(conversation.id, created.id)


class TestGetBody:
    async def test_body_inline_payload(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, body_cap_bytes=_CAP)
        event = await service.create(conversation.id, _payload())
        body = await service.get_body(conversation.id, event.id)
        assert json.loads(body) == event.body

    async def test_body_truncated_resolves_store(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store, body_cap_bytes=_CAP)
        big = {"text": "x" * (_CAP * 2)}
        event = await service.create(conversation.id, _payload(body=big))
        body = await service.get_body(conversation.id, event.id)
        assert json.loads(body) == big

    async def test_body_truncated_without_store_raises(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, body_cap_bytes=_CAP, store=None)
        big = {"text": "x" * (_CAP * 2)}
        event = await service.create(conversation.id, _payload(body=big))
        with pytest.raises(EventBodyNotFoundError):
            await service.get_body(conversation.id, event.id)

    async def test_body_truncated_malformed_store_entry_raises(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        """A missing, unparseable, or non-dict-body stored envelope is a 404-class error."""
        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store, body_cap_bytes=_CAP)
        big = {"text": "x" * (_CAP * 2)}
        event = await service.create(conversation.id, _payload(body=big))
        day = event.timestamp.date()

        for stored in list(Path(tmp_path).rglob("*.json")):
            stored.unlink()
        with pytest.raises(EventBodyNotFoundError):
            await service.get_body(conversation.id, event.id)

        store.store_body(event.id, day, b"not-json")
        with pytest.raises(EventBodyNotFoundError):
            await service.get_body(conversation.id, event.id)

        store.store_body(event.id, day, json.dumps({"body": "oops"}).encode())
        with pytest.raises(EventBodyNotFoundError):
            await service.get_body(conversation.id, event.id)


class TestSearchEvents:
    async def test_search_orders_by_timestamp(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        await service.create(conversation.id, _payload(kind="a"))
        await service.create(conversation.id, _payload(kind="b"))
        events, next_cursor = await service.search_events(conversation.id)
        assert [e.kind for e in events] == ["a", "b"]
        assert next_cursor is None

    async def test_search_cursor_paginates(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        for i in range(3):
            await service.create(conversation.id, _payload(kind=f"k{i}"))
        events, cursor = await service.search_events(conversation.id, limit=2)
        assert len(events) == 2
        assert cursor is not None
        rest, last_cursor = await service.search_events(conversation.id, limit=2, cursor=cursor)
        assert len(rest) == 1
        assert last_cursor is None

    async def test_search_filters_apply(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        await service.create(conversation.id, _payload(kind="message"))
        await service.create(conversation.id, _payload(kind="observation"))
        by_kind, _ = await service.search_events(
            conversation.id,
            search_filter=EventSearchFilter(kind__contains="message"),
        )
        assert [e.kind for e in by_kind] == ["message"]
        by_size, _ = await service.search_events(
            conversation.id, search_filter=EventSearchFilter(size_bytes__lt=2)
        )
        assert by_size == []

    async def test_search_scope_filters_rows(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL)
        await service.create(conversation.id, _payload())
        stranger = EventService(session, EventAccessFilter[Event](user_id=uuid.uuid4()))
        events, _ = await stranger.search_events(conversation.id)
        assert events == []


class TestBackfill:
    async def test_backfill_skips_existing_rows(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store, body_cap_bytes=_CAP)
        event = await service.create(conversation.id, _payload())
        run = await service.backfill()
        assert run == 0
        assert event.id is not None

    async def test_backfill_restores_missing_row(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store, body_cap_bytes=_CAP)
        event = await service.create(conversation.id, _payload())
        # Simulate the Postgres-down window: drop the row but keep the
        # envelope, then let backfill rebuild the row from the store.
        from openhands.ev2.event.event_models import Event as _Event

        row = await session.get(_Event, {"id": event.id, "timestamp": event.timestamp})
        assert row is not None
        await session.delete(row)
        await session.flush()
        restored = await EventService(session, ALL, store=store).backfill()
        assert restored == 1
        rebuilt = await service.get(conversation.id, event.id)
        assert rebuilt.id == event.id
        assert rebuilt.kind == event.kind
        assert rebuilt.size_bytes == event.size_bytes
        assert rebuilt.body == event.body

    async def test_backfill_no_store_restores_nothing(
        self, session: AsyncSession, conversation: Conversation
    ) -> None:
        service = EventService(session, ALL, store=None)
        assert await service.backfill() == 0

    async def test_backfill_tolerates_malformed_envelopes(
        self, session: AsyncSession, conversation: Conversation, tmp_path: Path
    ) -> None:
        """Unparseable/non-dict envelopes are skipped; a valid envelope with a
        non-dict body and no timestamp is rebuilt with an empty body and the
        object-key date."""
        store = FilesystemEventBodyStore(str(tmp_path))
        day = datetime(2025, 1, 2, tzinfo=UTC).date()
        store.store_body(uuid.uuid4(), day, b"not-json")
        store.store_body(uuid.uuid4(), day, json.dumps([1, 2]).encode())
        good_id = uuid.uuid4()
        store.store_body(
            good_id,
            day,
            json.dumps(
                {"conversation_id": str(conversation.id), "kind": "message", "body": "oops"}
            ).encode(),
        )
        service = EventService(session, ALL, store=store)
        assert await service.backfill() == 1
        rebuilt = await service.get(conversation.id, good_id)
        assert rebuilt.body == {}
        assert rebuilt.timestamp == datetime(2025, 1, 2, tzinfo=UTC)


class TestPartitions:
    async def test_ensure_partitions_is_idempotent(self, session: AsyncSession) -> None:
        service = EventService(session, ALL)
        created, dropped = await service.ensure_partitions(preallocate_days=2, retention_days=365)
        second, second_dropped = await service.ensure_partitions(
            preallocate_days=2, retention_days=365
        )
        # First run creates the future dated partitions; re-running is a
        # no-op.
        assert created != []
        assert all(name.startswith("events_") for name in created)
        assert dropped == []
        assert second == []
        assert second_dropped == []

    async def test_drop_expired_cleans_store_and_table(
        self, session: AsyncSession, tmp_path: Path
    ) -> None:
        from sqlalchemy import text

        store = FilesystemEventBodyStore(str(tmp_path))
        service = EventService(session, ALL, store=store)
        # Create an old dated partition and a body in the matching store
        # prefix; the sweep must drop the partition and remove the prefix.
        await session.execute(
            text(
                "CREATE TABLE IF NOT EXISTS events_20200101 "
                "PARTITION OF events FOR VALUES FROM ('2020-01-01') TO ('2020-01-02')"
            )
        )
        old_day = datetime(2020, 1, 1, tzinfo=UTC).date()
        store.store_body(uuid.uuid4(), old_day, b"{}")
        _created, dropped = await service.ensure_partitions(preallocate_days=1, retention_days=1)
        assert "events_20200101" in dropped
        # The store day-prefix was cleaned by the aligned sweep.
        assert not (Path(tmp_path) / "2020-01-01").exists()

    async def test_drop_prefix_is_tied_to_partition_drop(self, session: AsyncSession) -> None:
        # Computing the ISO day prefix out of a dropped partition name must
        # never be called for a non-drop case; a sweep that creates future
        # partitions and drops none touches no store prefixes.
        _created, dropped = await EventService(session, ALL).ensure_partitions(
            preallocate_days=1, retention_days=365
        )
        assert dropped == []
