"""Route tests for the event feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import ConversationCreate
from openhands.ev2.conversation.conversation_service import ConversationService
from openhands.ev2.event import event_router
from openhands.ev2.event.event_schemas import EventCreate
from openhands.ev2.event.event_service import EventService
from openhands.ev2.event.event_store import EventBodyStore, FilesystemEventBodyStore
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    from tests.unit._auth_helpers import make_principal

    return await make_principal(session, email="owner@example.com", username="owner")


@pytest.fixture
async def sandbox_config(session: AsyncSession, owner: User) -> SandboxConfig:
    from tests.unit._auth_helpers import make_sandbox_config

    return await make_sandbox_config(session, creator_id=owner.id)


@pytest.fixture
async def conversation(session: AsyncSession, sandbox_config: SandboxConfig) -> Conversation:
    """A real parent conversation for the route wiring."""
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


class TestCreateRoute:
    async def test_create_inline(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        resp = await client.post(
            f"/conversations/{conversation.id}/events",
            json=_payload({"outcome": "ok"}),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["kind"] == "test-signal"
        assert body["conversation_id"] == str(conversation.id)
        assert body["body"] == {"outcome": "ok"}

    async def test_create_unknown_conversation_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/conversations/{uuid.uuid4()}/events",
            json=_payload({"outcome": "ok"}),
        )
        assert resp.status_code == 404


class TestBatchWriteRoute:
    async def test_batch_create(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        resp = await client.post(
            f"/conversations/{conversation.id}/events/batch",
            json={
                "operations": [
                    {"data": {"kind": "test-signal", "body": {"i": 1}}},
                    {"op": "create", "data": {"kind": "test-signal", "body": {"i": 2}}},
                ]
            },
        )
        assert resp.status_code == 201, resp.text
        items = resp.json()["items"]
        assert [i["body"]["i"] for i in items] == [1, 2]
        assert all(i["conversation_id"] == str(conversation.id) for i in items)

    async def test_batch_unknown_conversation_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/conversations/{uuid.uuid4()}/events/batch",
            json={"operations": [{"data": {"kind": "k", "body": {}}}]},
        )
        assert resp.status_code == 404

    async def test_batch_empty_operations_422(self, client: AsyncClient, conversation) -> None:
        resp = await client.post(
            f"/conversations/{conversation.id}/events/batch",
            json={"operations": []},
        )
        assert resp.status_code == 422

    async def test_batch_create_denied_403(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        """A principal with no event create grant fails the guard (403)."""
        from tests.unit._auth_helpers import assign_role, make_principal

        from openhands.ev2.util.auth_token import create_auth_token

        principal = await make_principal(
            session,
            email=f"user-{uuid.uuid4().hex[:8]}@example.com",
            username=f"user-{uuid.uuid4().hex[:8]}",
        )
        await assign_role(session, principal.id, {"event_permission": None})
        await session.commit()
        resp = await client.post(
            f"/conversations/{conversation.id}/events/batch",
            json={"operations": [{"data": {"kind": "k", "body": {}}}]},
            headers={"Authorization": f"Bearer {create_auth_token(principal.id)}"},
        )
        assert resp.status_code == 403


class TestListRoute:
    async def test_list_paginated(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        svc = EventService(session, ALL)
        for i in range(3):
            await svc.create(conversation.id, _event_create({"i": i}))
        resp = await client.get(f"/conversations/{conversation.id}/events", params={"limit": 2})
        assert resp.status_code == 200, resp.text
        page = resp.json()
        assert len(page["items"]) == 2
        first_cursor = page["next_cursor"]
        assert first_cursor
        resp2 = await client.get(
            f"/conversations/{conversation.id}/events",
            params={"limit": 2, "cursor": first_cursor},
        )
        assert resp2.status_code == 200
        second = resp2.json()
        assert len(second["items"]) == 1
        i_values = {item["body"]["i"] for item in page["items"] + second["items"]}
        assert i_values == {0, 1, 2}

    async def test_list_invalid_cursor_400(self, client: AsyncClient, conversation) -> None:
        resp = await client.get(
            f"/conversations/{conversation.id}/events", params={"cursor": "not-a-cursor"}
        )
        assert resp.status_code == 400

    async def test_list_malformed_cursor_parts_400(self, client: AsyncClient, conversation) -> None:
        resp = await client.get(
            f"/conversations/{conversation.id}/events", params={"cursor": "junk|junk"}
        )
        assert resp.status_code == 400


class TestGetRoute:
    async def test_get(self, client: AsyncClient, session: AsyncSession, conversation) -> None:
        svc = EventService(session, ALL)
        event = await svc.create(conversation.id, _event_create({"outcome": "ok"}))
        resp = await client.get(f"/conversations/{conversation.id}/events/{event.id}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == str(event.id)

    async def test_get_missing_404(self, client: AsyncClient, conversation) -> None:
        resp = await client.get(f"/conversations/{conversation.id}/events/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_wrong_conversation_404(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        svc = EventService(session, ALL)
        event = await svc.create(conversation.id, _event_create({"outcome": "ok"}))
        resp = await client.get(f"/conversations/{uuid.uuid4()}/events/{event.id}")
        assert resp.status_code == 404


class TestBodyRoute:
    async def test_inline_body(
        self, client: AsyncClient, session: AsyncSession, conversation
    ) -> None:
        svc = EventService(session, ALL)
        event = await svc.create(conversation.id, _event_create({"outcome": "ok"}))
        resp = await client.get(f"/conversations/{conversation.id}/events/{event.id}/body")
        assert resp.status_code == 200, resp.text
        assert json.loads(resp.content) == {"outcome": "ok"}

    async def test_truncated_body_from_store(
        self,
        client: AsyncClient,
        session: AsyncSession,
        conversation,
        tmp_path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = FilesystemEventBodyStore(str(tmp_path))
        svc: EventService = EventService(session, ALL, store=store, body_cap_bytes=64)
        event = await svc.create(conversation.id, _event_create({"big": "x" * 512}))

        class FakeCfg:
            event = SimpleNamespace(body_cap_bytes=64)

            def get_event_store(self) -> EventBodyStore:
                return store

        monkeypatch.setattr(event_router, "get_config", lambda: FakeCfg())
        resp = await client.get(f"/conversations/{conversation.id}/events/{event.id}/body")
        assert resp.status_code == 200, resp.text
        assert json.loads(resp.content) == {"big": "x" * 512}

    async def test_truncated_body_missing_store_404(
        self,
        client: AsyncClient,
        session: AsyncSession,
        conversation,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        svc = EventService(session, ALL, body_cap_bytes=64)
        event = await svc.create(conversation.id, _event_create({"big": "x" * 512}))

        class FakeCfg:
            event = SimpleNamespace(body_cap_bytes=64)

            def get_event_store(self) -> EventBodyStore | None:
                return None

        monkeypatch.setattr(event_router, "get_config", lambda: FakeCfg())
        resp = await client.get(f"/conversations/{conversation.id}/events/{event.id}/body")
        assert resp.status_code == 404


def _payload(body: object) -> dict[str, object]:
    return {
        "kind": "test-signal",
        "timestamp": datetime.now(UTC).isoformat(),
        "body": body,
    }


def _event_create(body: object) -> EventCreate:
    """Service-input payload (routes take the dict shape above)."""
    return EventCreate(
        kind="test-signal",
        timestamp=datetime.now(UTC),
        body=body,  # type: ignore[arg-type]
    )
