"""Route tests for the legacy agent-server webhook adapter (/webhooks/*).

The adapter receives SDK-shaped payloads authenticated with the sandbox
session key (``X-Session-API-Key``) and translates them into ohev2
conversations/events rows. All requests here use an unauthenticated client —
the webhook surface is sandbox-only and deliberately rejects user
credentials.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from openhands.agent_server.models import ConversationInfo
from openhands.sdk import LLM, Agent
from openhands.sdk.conversation.conversation_stats import ConversationStats
from openhands.sdk.event import ConversationStateUpdateEvent, MessageEvent
from openhands.sdk.llm import TokenUsage
from openhands.sdk.llm.utils.metrics import Metrics
from openhands.sdk.workspace import LocalWorkspace
from tests.unit._auth_helpers import (
    make_sandbox_config as _make_sandbox_config,
)

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.webhook import webhook_service

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")

SESSION_KEY = "webhook-session-key"

# The SDK emits a deprecation warning when validating a serialized LLM that
# carries the (legacy-default) modify_params field — real agent-server
# payloads include it. Production only logs warnings; tests error on them.
pytestmark = pytest.mark.filterwarnings(
    "ignore:LLM.modify_params is deprecated:openhands.sdk.utils.deprecation.DeprecatedWarning"
)


@pytest_asyncio.fixture
async def sandbox_client(app) -> AsyncGenerator[AsyncClient, None]:
    """An HTTP client with no user credential; sandbox key set per request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _session_headers(key: str = SESSION_KEY) -> dict[str, str]:
    return {"X-Session-API-Key": key}


def _stats(cost: float, prompt: int, completion: int) -> ConversationStats:
    return ConversationStats(
        usage_to_metrics={
            "test-llm": Metrics(
                model_name="test-model",
                accumulated_cost=cost,
                accumulated_token_usage=TokenUsage(
                    model="test-model",
                    prompt_tokens=prompt,
                    completion_tokens=completion,
                ),
            )
        }
    )


def _conversation_info_payload(
    conversation_id: uuid.UUID | None = None,
    *,
    title: str = "webhook conversation",
    execution_status: str = "running",
    stats: ConversationStats | None = None,
) -> dict[str, Any]:
    llm = LLM(model="test-model", usage_id="test-llm")
    kwargs: dict[str, Any] = {}
    if stats is not None:
        kwargs["stats"] = stats
    info = ConversationInfo(
        id=conversation_id or uuid.uuid4(),
        agent=Agent(llm=llm, tools=[]),
        workspace=LocalWorkspace(working_dir="/tmp/workspace"),
        title=title,
        execution_status=execution_status,
        **kwargs,
    )
    return info.model_dump(mode="json", by_alias=True)


def _message_event_payload(text: str) -> dict[str, Any]:
    event = MessageEvent(
        source="user",
        llm_message={"role": "user", "content": [{"type": "text", "text": text}]},
    )
    return event.model_dump(mode="json")


def _stats_event_payload(stats: ConversationStats) -> dict[str, Any]:
    event = ConversationStateUpdateEvent(
        source="agent", key="stats", value=stats.model_dump(mode="json")
    )
    return event.model_dump(mode="json")


async def _make_conversation(session, sandbox_config_id: uuid.UUID) -> Conversation:
    conversation = Conversation(
        title="existing",
        sandbox_config_id=sandbox_config_id,
        llm_model="claude-sonnet-4",
        agent_kind="openhands",
        trigger="manual",
    )
    session.add(conversation)
    await session.flush()
    return conversation


class TestConversationWebhookAuth:
    async def test_missing_key_401(self, sandbox_client: AsyncClient) -> None:
        resp = await sandbox_client.post(
            "/webhooks/conversations", json=_conversation_info_payload()
        )
        assert resp.status_code == 401

    async def test_unknown_key_401(self, sandbox_client: AsyncClient, session) -> None:
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers("bogus"),
            json=_conversation_info_payload(),
        )
        assert resp.status_code == 401

    async def test_user_credential_not_accepted(self, client: AsyncClient, session) -> None:
        """The webhook surface is sandbox-only: a valid user Bearer is a 401."""
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await client.post("/webhooks/conversations", json=_conversation_info_payload())
        assert resp.status_code == 401


class TestConversationWebhookUpsert:
    async def test_creates_conversation(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        config = await _make_sandbox_config(
            session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY
        )
        await session.commit()

        conversation_id = uuid.uuid4()
        resp = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers(),
            json=_conversation_info_payload(
                conversation_id, title="from webhook", stats=_stats(1.5, 100, 50)
            ),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"success": True}

        # The row is aligned with the agent server's conversation id and is
        # visible to the owning user through the normal API.
        get_resp = await client.get(f"/conversations/{conversation_id}")
        assert get_resp.status_code == 200, get_resp.text
        body = get_resp.json()
        assert body["sandbox_config_id"] == str(config.id)
        assert body["title"] == "from webhook"
        assert body["llm_model"] == "test-model"
        assert body["agent_kind"] == "openhands"
        assert body["trigger"] == "webhook"
        assert body["accumulated_cost"] == 1.5
        assert body["prompt_tokens"] == 100
        assert body["completion_tokens"] == 50
        assert body["total_tokens"] == 150

    async def test_updates_existing_metadata_and_metrics(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY)
        await session.commit()
        conversation_id = uuid.uuid4()
        first = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers(),
            json=_conversation_info_payload(
                conversation_id, title="first", stats=_stats(1.0, 10, 5)
            ),
        )
        assert first.status_code == 200, first.text

        second = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers(),
            json=_conversation_info_payload(
                conversation_id, title="renamed", stats=_stats(3.0, 30, 15)
            ),
        )
        assert second.status_code == 200, second.text

        body = (await client.get(f"/conversations/{conversation_id}")).json()
        assert body["title"] == "renamed"
        assert body["accumulated_cost"] == 3.0
        assert body["total_tokens"] == 45

    async def test_cross_sandbox_upsert_404(self, sandbox_client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(
            session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY
        )
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key="other")
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        resp = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers("other"),
            json=_conversation_info_payload(conversation.id),
        )
        assert resp.status_code == 404

    async def test_deleting_status_is_noop(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY)
        await session.commit()
        conversation_id = uuid.uuid4()
        resp = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers(),
            json=_conversation_info_payload(conversation_id, execution_status="deleting"),
        )
        assert resp.status_code == 200, resp.text
        assert (await client.get(f"/conversations/{conversation_id}")).status_code == 404


class TestEventWebhook:
    async def _setup(self, sandbox_client: AsyncClient, session) -> uuid.UUID:
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY)
        await session.commit()
        conversation_id = uuid.uuid4()
        resp = await sandbox_client.post(
            "/webhooks/conversations",
            headers=_session_headers(),
            json=_conversation_info_payload(conversation_id),
        )
        assert resp.status_code == 200, resp.text
        return conversation_id

    async def test_appends_events_and_folds_stats(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        conversation_id = await self._setup(sandbox_client, session)
        stats = _stats(2.5, 200, 100)
        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation_id}",
            headers=_session_headers(),
            json=[_message_event_payload("hi"), _stats_event_payload(stats)],
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"success": True}

        events_resp = await client.get(f"/conversations/{conversation_id}/events")
        assert events_resp.status_code == 200
        items = events_resp.json()["items"]
        assert [item["kind"] for item in items] == [
            "MessageEvent",
            "ConversationStateUpdateEvent",
        ]

        body = (await client.get(f"/conversations/{conversation_id}")).json()
        assert body["accumulated_cost"] == 2.5
        assert body["prompt_tokens"] == 200
        assert body["completion_tokens"] == 100
        assert body["total_tokens"] == 300

    async def test_preserves_event_timestamp(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        conversation_id = await self._setup(sandbox_client, session)
        event = MessageEvent(
            source="user",
            llm_message={"role": "user", "content": [{"type": "text", "text": "hi"}]},
        )
        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation_id}",
            headers=_session_headers(),
            json=[event.model_dump(mode="json")],
        )
        assert resp.status_code == 200, resp.text

        items = (await client.get(f"/conversations/{conversation_id}/events")).json()["items"]
        assert len(items) == 1
        assert items[0]["timestamp"].startswith(event.timestamp[:19])

    async def test_unknown_conversation_404(self, sandbox_client: AsyncClient, session) -> None:
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key=SESSION_KEY)
        await session.commit()
        resp = await sandbox_client.post(
            f"/webhooks/events/{uuid.uuid4()}",
            headers=_session_headers(),
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 404

    async def test_cross_sandbox_events_404(self, sandbox_client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await _make_sandbox_config(session, creator_id=_TEST_USER_ID, session_key="other")
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation.id}",
            headers=_session_headers("other"),
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 404

    async def test_missing_key_401(self, sandbox_client: AsyncClient) -> None:
        resp = await sandbox_client.post(
            f"/webhooks/events/{uuid.uuid4()}", json=[_message_event_payload("hi")]
        )
        assert resp.status_code == 401

    async def test_empty_batch_ok(self, sandbox_client: AsyncClient, session) -> None:
        conversation_id = await self._setup(sandbox_client, session)
        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation_id}", headers=_session_headers(), json=[]
        )
        assert resp.status_code == 200, resp.text

    async def test_unparseable_stats_value_skips_metrics(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        conversation_id = await self._setup(sandbox_client, session)
        event = ConversationStateUpdateEvent(source="agent", key="stats", value={"garbage": True})
        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation_id}",
            headers=_session_headers(),
            json=[event.model_dump(mode="json")],
        )
        assert resp.status_code == 200, resp.text
        row = (await client.get(f"/conversations/{conversation_id}")).json()
        assert row["accumulated_cost"] == 0
        assert row["total_tokens"] == 0

    async def test_stats_without_token_usage_updates_cost_only(
        self, sandbox_client: AsyncClient, client: AsyncClient, session
    ) -> None:
        conversation_id = await self._setup(sandbox_client, session)
        stats = ConversationStats(
            usage_to_metrics={"test-llm": Metrics(model_name="m", accumulated_cost=2.5)}
        )
        resp = await sandbox_client.post(
            f"/webhooks/events/{conversation_id}",
            headers=_session_headers(),
            json=[_stats_event_payload(stats)],
        )
        assert resp.status_code == 200, resp.text
        row = (await client.get(f"/conversations/{conversation_id}")).json()
        assert row["accumulated_cost"] == 2.5
        assert row["total_tokens"] == 0


class TestParsingHelpers:
    def test_stats_from_value_accepts_instance(self) -> None:
        stats = ConversationStats()
        assert webhook_service._stats_from_value(stats) is stats

    def test_event_timestamp_unparseable_returns_none(self) -> None:
        assert webhook_service._event_timestamp("not-a-date") is None

    def test_import_all_tools_tolerates_broken_subpackage(self, monkeypatch) -> None:
        from openhands.ev2.webhook import webhook_router

        def _raise(name: str) -> None:
            raise ImportError(name)

        monkeypatch.setattr(webhook_router.importlib, "import_module", _raise)
        webhook_router._import_all_tools()
