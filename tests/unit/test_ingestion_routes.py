"""Route tests for the scoped sandbox ingestion path.

The ingestion endpoints (``PATCH /conversations/{id}``,
``POST /conversations/{id}/events``) accept either a user credential (the
standard role-policy path, covered by the resource route tests) or the
sandbox session key in the ``X-Session-API-Key`` header, scoped to the
sandbox's own conversations. These tests exercise the session-key path over
HTTP with an otherwise-unauthenticated client.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from tests.unit._auth_helpers import (
    make_sandbox_config as _make_sandbox_config,
)

from openhands.ev2.conversation.conversation_models import Conversation

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")

SESSION_KEY = "ingestion-session-key"


@pytest_asyncio.fixture
async def sandbox_client(app) -> AsyncGenerator[AsyncClient, None]:
    """An HTTP client with no user credential; sandbox key set per request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _session_headers(key: str = SESSION_KEY) -> dict[str, str]:
    return {"X-Session-API-Key": key}


async def _make_conversation(session, sandbox_config_id: uuid.UUID) -> Conversation:
    conversation = Conversation(
        title="ingestion target",
        sandbox_config_id=sandbox_config_id,
        llm_model="claude-sonnet-4",
        agent_kind="openhands",
        trigger="manual",
    )
    session.add(conversation)
    await session.flush()
    return conversation


class TestPatchConversationIngestion:
    async def test_session_key_updates_metadata_and_metrics(
        self, sandbox_client: AsyncClient, session
    ) -> None:
        config = await _make_sandbox_config(
            session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY
        )
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.patch(
            f"/conversations/{conversation.id}",
            headers=_session_headers(),
            json={
                "title": "updated by sandbox",
                "accumulated_cost": 1.25,
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["title"] == "updated by sandbox"
        assert body["accumulated_cost"] == 1.25
        assert body["prompt_tokens"] == 100
        assert body["completion_tokens"] == 50
        assert body["total_tokens"] == 150

    async def test_other_sandbox_key_gets_404(self, sandbox_client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key="other-key")
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        resp = await sandbox_client.patch(
            f"/conversations/{conversation.id}",
            headers=_session_headers("other-key"),
            json={"title": "must not apply"},
        )
        assert resp.status_code == 404

    async def test_unknown_key_gets_401(self, sandbox_client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.patch(
            f"/conversations/{conversation.id}",
            headers=_session_headers("bogus"),
            json={"title": "nope"},
        )
        assert resp.status_code == 401

    async def test_anonymous_denied(self, sandbox_client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.patch(
            f"/conversations/{conversation.id}", json={"title": "nope"}
        )
        assert resp.status_code in (401, 403)

    async def test_session_key_cannot_delete(self, sandbox_client: AsyncClient, session) -> None:
        """The sandbox credential scopes update only — DELETE stays user-only."""
        config = await _make_sandbox_config(
            session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY
        )
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.delete(
            f"/conversations/{conversation.id}", headers=_session_headers()
        )
        assert resp.status_code in (401, 403)


class TestCreateEventIngestion:
    async def test_session_key_appends_event(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        config = await _make_sandbox_config(
            session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY
        )
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.post(
            f"/conversations/{conversation.id}/events",
            headers=_session_headers(),
            json={"kind": "MessageEvent", "body": {"text": "hello"}},
        )
        assert resp.status_code == 201, resp.text
        event_id = resp.json()["id"]

        # The owning user reads the appended event back.
        get_resp = await client.get(f"/conversations/{conversation.id}/events/{event_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["kind"] == "MessageEvent"

    async def test_other_sandbox_key_gets_403(self, sandbox_client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key="other-key")
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        resp = await sandbox_client.post(
            f"/conversations/{conversation.id}/events",
            headers=_session_headers("other-key"),
            json={"kind": "MessageEvent", "body": {"text": "nope"}},
        )
        assert resp.status_code == 403

    async def test_unknown_key_gets_401(self, sandbox_client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.post(
            f"/conversations/{conversation.id}/events",
            headers=_session_headers("bogus"),
            json={"kind": "MessageEvent", "body": {}},
        )
        assert resp.status_code == 401

    async def test_anonymous_denied(self, sandbox_client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        await session.commit()

        resp = await sandbox_client.post(
            f"/conversations/{conversation.id}/events",
            json={"kind": "MessageEvent", "body": {}},
        )
        assert resp.status_code in (401, 403)
