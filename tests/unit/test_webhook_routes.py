"""Route tests for the legacy agent-server webhook adapter (/webhooks/*).

The adapter receives SDK-shaped payloads and translates them into ohev2
conversations/events rows. Authorization is the standard credential path:
the default ``client`` fixture acts as the test principal (whose seeded
admin role permits every action); restricted-principal tests mint a user +
role and authenticate via ``X-API-Key``.
"""

from __future__ import annotations

import uuid
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
from tests.unit._auth_helpers import assign_role, make_principal
from tests.unit._auth_helpers import make_sandbox_config as _make_sandbox_config

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_security import ConversationAccess
from openhands.ev2.event.event_security import EventAccess
from openhands.ev2.security.security_models import (
    AclPermission,
    Permission,
    Permitted,
)
from openhands.ev2.util.auth_token import create_auth_token
from openhands.ev2.webhook import webhook_service

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")

# The SDK emits a deprecation warning when validating a serialized LLM that
# carries the (legacy-default) modify_params field — real agent-server
# payloads include it. Production only logs warnings; tests error on them.
pytestmark = pytest.mark.filterwarnings(
    "ignore:LLM.modify_params is deprecated:openhands.sdk.utils.deprecation.DeprecatedWarning"
)


@pytest_asyncio.fixture
async def noauth_client(app) -> AsyncClient:
    """An HTTP client WITHOUT the default Bearer credential (anonymous)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _principal_token(session, perms: dict[str, Permission | None]) -> str:
    """A new user with *perms* on one fresh role; returns an API-key token."""
    principal = await make_principal(
        session,
        email=f"user-{uuid.uuid4().hex[:8]}@example.com",
        username=f"user-{uuid.uuid4().hex[:8]}",
    )
    await assign_role(session, principal.id, perms)
    return create_auth_token(principal.id)


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


class TestConversationWebhookScope:
    async def test_missing_credentials_403(self, noauth_client: AsyncClient, session) -> None:
        """No credential means no roles — the standard guard denies (403)."""
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await noauth_client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(),
        )
        assert resp.status_code == 403

    async def test_unknown_sandbox_config_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/webhooks/{uuid.uuid4()}/conversations",
            json=_conversation_info_payload(),
        )
        assert resp.status_code == 404

    async def test_create_denied_403(self, client: AsyncClient, session) -> None:
        """A role with no conversation grant fails the guard (403)."""
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        token = await _principal_token(session, {"conversation_permission": None})
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(),
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403

    async def test_create_scoped_policy_403(self, client: AsyncClient, session) -> None:
        """A deny-filtered role drops straight through the guard (403).

        Service-level in-memory mismatches are covered in
        ``test_webhook_service.py``; at route level reduced deny filters
        collapse to ``None`` and fail the guard.
        """
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        token = await _principal_token(session, {"conversation_permission": ConversationAccess()})
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(),
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403


class TestConversationWebhookUpsert:
    async def test_creates_conversation(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()

        conversation_id = uuid.uuid4()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
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
        self, client: AsyncClient, session
    ) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        conversation_id = uuid.uuid4()
        first = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(
                conversation_id, title="first", stats=_stats(1.0, 10, 5)
            ),
        )
        assert first.status_code == 200, first.text

        second = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(
                conversation_id, title="renamed", stats=_stats(3.0, 30, 15)
            ),
        )
        assert second.status_code == 200, second.text

        body = (await client.get(f"/conversations/{conversation_id}")).json()
        assert body["title"] == "renamed"
        assert body["accumulated_cost"] == 3.0
        assert body["total_tokens"] == 45

    async def test_cross_sandbox_upsert_404(self, client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        config_b = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        # The URL's config is B but the row belongs to A — invisible (404).
        resp = await client.post(
            f"/webhooks/{config_b.id}/conversations",
            json=_conversation_info_payload(conversation.id),
        )
        assert resp.status_code == 404

    async def test_update_filter_mismatch_404(self, client: AsyncClient, session) -> None:
        """A granted create whose update filter denies the existing row → 404."""
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        token = await _principal_token(
            session,
            # Full create + full access to ONE unrelated conversation id; the
            # target row (different id) is denied by the update filter.
            {
                "conversation_permission": AclPermission(
                    item_ids=[uuid.uuid4()],
                    on_match=Permitted(),
                    on_create=Permitted(),
                )
            },
        )
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(conversation.id),
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 404

    async def test_deleting_status_is_noop(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        conversation_id = uuid.uuid4()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(conversation_id, execution_status="deleting"),
        )
        assert resp.status_code == 200, resp.text
        assert (await client.get(f"/conversations/{conversation_id}")).status_code == 404


class TestEventWebhook:
    async def _setup(self, client: AsyncClient, session) -> tuple[uuid.UUID, uuid.UUID]:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        conversation_id = uuid.uuid4()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations",
            json=_conversation_info_payload(conversation_id),
        )
        assert resp.status_code == 200, resp.text
        return config.id, conversation_id

    async def test_appends_events_and_folds_stats(self, client: AsyncClient, session) -> None:
        config_id, conversation_id = await self._setup(client, session)
        stats = _stats(2.5, 200, 100)
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
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

    async def test_preserves_event_timestamp(self, client: AsyncClient, session) -> None:
        config_id, conversation_id = await self._setup(client, session)
        event = MessageEvent(
            source="user",
            llm_message={"role": "user", "content": [{"type": "text", "text": "hi"}]},
        )
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[event.model_dump(mode="json")],
        )
        assert resp.status_code == 200, resp.text

        items = (await client.get(f"/conversations/{conversation_id}/events")).json()["items"]
        assert len(items) == 1
        assert items[0]["timestamp"].startswith(event.timestamp[:19])

    async def test_unknown_conversation_404(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config.id}/conversations/{uuid.uuid4()}/events",
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 404

    async def test_cross_sandbox_events_404(self, client: AsyncClient, session) -> None:
        config_a = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        config_b = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config_a.id)
        await session.commit()

        resp = await client.post(
            f"/webhooks/{config_b.id}/conversations/{conversation.id}/events",
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 404

    async def test_missing_credentials_403(self, noauth_client: AsyncClient) -> None:
        resp = await noauth_client.post(
            f"/webhooks/{uuid.uuid4()}/conversations/{uuid.uuid4()}/events",
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 403

    async def test_event_create_denied_403(self, client: AsyncClient, session) -> None:
        config_id, conversation_id = await self._setup(client, session)
        token = await _principal_token(
            session,
            {
                "conversation_permission": Permitted(),
                # No event grant → the hard Event CREATE guard denies (403).
                "event_permission": None,
            },
        )
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[_message_event_payload("hi")],
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403

    async def test_event_scoped_policy_403(self, client: AsyncClient, session) -> None:
        """A scoped (deny-filter) event role drops through the guard (403)."""
        config_id, conversation_id = await self._setup(client, session)
        token = await _principal_token(
            session,
            {
                "conversation_permission": Permitted(),
                "event_permission": EventAccess(),
            },
        )
        await session.commit()
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[_message_event_payload("hi")],
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 403

    async def test_missing_update_filter_skips_stats_fold(
        self, client: AsyncClient, session
    ) -> None:
        """Without Conversation UPDATE the stats fold is skipped (events ok)."""
        config_id, conversation_id = await self._setup(client, session)
        token = await _principal_token(
            session,
            {
                # No conversation UPDATE grant (None) — ConversationAccess
                # denies non-read actions — but full event create.
                "conversation_permission": AclPermission(
                    item_ids=[uuid.uuid4()], on_match=Permitted(), on_create=Permitted()
                ),
                "event_permission": Permitted(),
            },
        )
        await session.commit()

        stats = _stats(2.5, 200, 100)
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[_stats_event_payload(stats)],
            headers={"X-API-Key": token},
        )
        assert resp.status_code == 200, resp.text

        body = (await client.get(f"/conversations/{conversation_id}")).json()
        assert body["accumulated_cost"] == 0
        assert body["total_tokens"] == 0

        items = (await client.get(f"/conversations/{conversation_id}/events")).json()["items"]
        assert [item["kind"] for item in items] == ["ConversationStateUpdateEvent"]

    async def test_empty_batch_ok(self, client: AsyncClient, session) -> None:
        config_id, conversation_id = await self._setup(client, session)
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events", json=[]
        )
        assert resp.status_code == 200, resp.text

    async def test_unparseable_stats_value_skips_metrics(
        self, client: AsyncClient, session
    ) -> None:
        config_id, conversation_id = await self._setup(client, session)
        event = ConversationStateUpdateEvent(source="agent", key="stats", value={"garbage": True})
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[event.model_dump(mode="json")],
        )
        assert resp.status_code == 200, resp.text
        row = (await client.get(f"/conversations/{conversation_id}")).json()
        assert row["accumulated_cost"] == 0
        assert row["total_tokens"] == 0

    async def test_stats_without_token_usage_updates_cost_only(
        self, client: AsyncClient, session
    ) -> None:
        config_id, conversation_id = await self._setup(client, session)
        stats = ConversationStats(
            usage_to_metrics={"test-llm": Metrics(model_name="m", accumulated_cost=2.5)}
        )
        resp = await client.post(
            f"/webhooks/{config_id}/conversations/{conversation_id}/events",
            json=[_stats_event_payload(stats)],
        )
        assert resp.status_code == 200, resp.text
        row = (await client.get(f"/conversations/{conversation_id}")).json()
        assert row["accumulated_cost"] == 2.5
        assert row["total_tokens"] == 0

    async def test_unknown_sandbox_config_404(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        conversation = await _make_conversation(session, config.id)
        await session.commit()
        # The URL's config id must exist but not own the conversation.
        resp = await client.post(
            f"/webhooks/{uuid.uuid4()}/conversations/{conversation.id}/events",
            json=[_message_event_payload("hi")],
        )
        assert resp.status_code == 404


class TestParsingHelpers:
    def test_stats_from_value_accepts_instance(self) -> None:
        stats = ConversationStats()
        assert webhook_service._stats_from_value(stats) is stats

    def test_stats_from_value_unparseable_dict_returns_none(self) -> None:
        assert webhook_service._stats_from_value({"usage_to_metrics": 1}) is None

    def test_metrics_from_stats_without_token_usage_cost_only(self) -> None:
        stats = ConversationStats(
            usage_to_metrics={"test-llm": Metrics(model_name="m", accumulated_cost=2.5)}
        )
        assert webhook_service._metrics_from_stats(stats) == {
            "accumulated_cost": 2.5,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }

    def test_event_timestamp_unparseable_returns_none(self) -> None:
        assert webhook_service._event_timestamp("not-a-date") is None

    def test_import_all_tools_tolerates_broken_subpackage(self, monkeypatch) -> None:
        from openhands.ev2.webhook import webhook_router

        def _raise(name: str) -> None:
            raise ImportError(name)

        monkeypatch.setattr(webhook_router.importlib, "import_module", _raise)
        webhook_router._import_all_tools()
