"""Unit tests for the embedded event-callback model (issue #159).

Event callbacks are no longer a standalone governed resource: they are a
polymorphic Pydantic model stored as a JSONB list on ``Conversation`` (and
``default_callbacks`` on ``ConversationTemplate``). These tests cover:

* the ``EventCallback`` JSON round-trip (serialize/deserialize restores the
  concrete subclass)
* ``LoggingCallback.__call__`` invoking against a batch of events
* the ``Conversation.event_callbacks`` typed column (create, read, update)
* the ``ConversationTemplate.default_callbacks`` typed column (create, read)

Dispatch/invocation against real conversation events is out of scope (the
future generic job queue owns it).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal, make_sandbox_config

from openhands.ev2.conversation.conversation_schemas import ConversationCreate
from openhands.ev2.conversation.conversation_service import ConversationService
from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateCreate,
)
from openhands.ev2.conversation_template.conversation_template_service import (
    ConversationTemplateService,
)
from openhands.ev2.event_callback.event_callback_models import (
    EventCallback,
    LoggingCallback,
)
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL

pytestmark = pytest.mark.asyncio


def _logging_callback(level: str = "info") -> LoggingCallback:
    return LoggingCallback(level=level)


def _logging_callback_json(level: str = "info") -> dict[str, Any]:
    return _logging_callback(level).model_dump(mode="json")


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="cb-owner@example.com", username="cb-owner")


@pytest.fixture
async def sandbox_config(session: AsyncSession, owner: User) -> SandboxConfig:
    return await make_sandbox_config(session, creator_id=owner.id)


def _conv_create_payload(sandbox_config_id: uuid.UUID) -> ConversationCreate:
    return ConversationCreate(
        title="cb-test",
        sandbox_config_id=sandbox_config_id,
        llm_model="claude-sonnet-4",
        agent_kind="openhands",
        selected_repository=None,
        selected_branch=None,
        trigger="manual",
    )


# --------------------------------------------------------------------------- #
# EventCallback model round-trip
# --------------------------------------------------------------------------- #


class TestEventCallbackRoundTrip:
    async def test_serializes_and_deserializes_concrete_subclass(self) -> None:
        callback = LoggingCallback(level="debug")
        data = callback.model_dump(mode="json")
        assert data["kind"] == "LoggingCallback"
        round_tripped = EventCallback.model_validate(data)
        assert isinstance(round_tripped, LoggingCallback)
        assert round_tripped.level == "debug"

    async def test_round_trip_preserves_concrete_subclass_through_union(self) -> None:
        original = LoggingCallback()
        data = original.model_dump(mode="json")
        restored = EventCallback.model_validate(data)
        assert type(restored) is LoggingCallback
        assert restored == original

    async def test_dict_input_routes_to_concrete_subclass(self) -> None:
        restored = EventCallback.model_validate({"kind": "LoggingCallback", "level": "warning"})
        assert isinstance(restored, LoggingCallback)
        assert restored.level == "warning"


# --------------------------------------------------------------------------- #
# LoggingCallback.__call__
# --------------------------------------------------------------------------- #


class TestLoggingCallbackCall:
    async def test_logs_every_event_in_the_batch(self, caplog: pytest.LogCaptureFixture) -> None:
        events: list[Any] = [object(), object(), object()]
        callback = LoggingCallback(level="info")
        with caplog.at_level(logging.INFO, logger="openhands.ev2.event_callback"):
            await callback(events)
        records = [r for r in caplog.records if r.name == "openhands.ev2.event_callback"]
        assert len(records) == 3
        for record in records:
            assert record.levelno == logging.INFO

    async def test_respects_configured_level(self, caplog: pytest.LogCaptureFixture) -> None:
        events: list[Any] = [object()]
        callback = LoggingCallback(level="debug")
        with caplog.at_level(logging.DEBUG, logger="openhands.ev2.event_callback"):
            await callback(events)
        records = [r for r in caplog.records if r.name == "openhands.ev2.event_callback"]
        assert len(records) == 1
        assert records[0].levelno == logging.DEBUG

    async def test_empty_batch_logs_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        callback = LoggingCallback()
        with caplog.at_level(logging.INFO, logger="openhands.ev2.event_callback"):
            await callback([])
        records = [r for r in caplog.records if r.name == "openhands.ev2.event_callback"]
        assert records == []


# --------------------------------------------------------------------------- #
# Conversation.event_callbacks typed column
# --------------------------------------------------------------------------- #


class TestConversationEventCallbacks:
    async def test_create_defaults_to_empty(
        self, session: AsyncSession, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, ALL)
        conversation = await service.create(_conv_create_payload(sandbox_config.id))
        assert conversation.event_callbacks == []
        fetched = await service.get(conversation.id)
        assert fetched.event_callbacks == []

    async def test_create_persists_and_round_trips_callbacks(
        self, session: AsyncSession, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, ALL)
        payload = _conv_create_payload(sandbox_config.id)
        payload.event_callbacks = [LoggingCallback(level="debug"), LoggingCallback()]
        conversation = await service.create(payload)
        assert len(conversation.event_callbacks) == 2
        assert all(isinstance(c, LoggingCallback) for c in conversation.event_callbacks)
        fetched = await service.get(conversation.id)
        assert [type(c) for c in fetched.event_callbacks] == [LoggingCallback, LoggingCallback]
        assert fetched.event_callbacks[0].level == "debug"
        assert fetched.event_callbacks[1].level == "info"

    async def test_update_replaces_callbacks(
        self, session: AsyncSession, sandbox_config: SandboxConfig
    ) -> None:
        from openhands.ev2.conversation.conversation_schemas import ConversationUpdate

        service = ConversationService(session, ALL)
        conversation = await service.create(_conv_create_payload(sandbox_config.id))
        updated = await service.update(
            conversation.id,
            ConversationUpdate(event_callbacks=[LoggingCallback(level="warning")]),
        )
        assert len(updated.event_callbacks) == 1
        assert isinstance(updated.event_callbacks[0], LoggingCallback)
        assert updated.event_callbacks[0].level == "warning"


# --------------------------------------------------------------------------- #
# ConversationTemplate.default_callbacks typed column
# --------------------------------------------------------------------------- #


class TestConversationTemplateDefaultCallbacks:
    async def test_create_defaults_to_empty(self, session: AsyncSession, owner: User) -> None:
        service = ConversationTemplateService(session, ALL)
        template = await service.create(
            ConversationTemplateCreate(
                name="cb-test-template",
                agent_config={"agent": "CodeActAgent"},
                conversation_config={"max_iterations": 100},
            ),
            creator_id=owner.id,
        )
        assert template.default_callbacks == []

    async def test_create_persists_and_round_trips_callbacks(
        self, session: AsyncSession, owner: User
    ) -> None:
        service = ConversationTemplateService(session, ALL)
        template = await service.create(
            ConversationTemplateCreate(
                name="cb-test-template",
                agent_config={"agent": "CodeActAgent"},
                conversation_config={"max_iterations": 100},
                default_callbacks=[LoggingCallback(level="debug")],
            ),
            creator_id=owner.id,
        )
        assert len(template.default_callbacks) == 1
        callback = template.default_callbacks[0]
        assert isinstance(callback, LoggingCallback)
        assert callback.level == "debug"


# --------------------------------------------------------------------------- #
# HTTP routes — event_callbacks embedded on conversations
# --------------------------------------------------------------------------- #


class TestConversationEventCallbackRoutes:
    async def test_create_with_callbacks_round_trips(
        self, client: AsyncClient, sandbox_config: SandboxConfig
    ) -> None:
        payload = {
            "title": "cb-route",
            "sandbox_config_id": str(sandbox_config.id),
            "llm_model": "claude-sonnet-4",
            "agent_kind": "openhands",
            "trigger": "manual",
            "event_callbacks": [_logging_callback_json("debug")],
        }
        resp = await client.post("/conversations", json=payload)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert len(body["event_callbacks"]) == 1
        assert body["event_callbacks"][0]["kind"] == "LoggingCallback"
        assert body["event_callbacks"][0]["level"] == "debug"

    async def test_update_callbacks(
        self, client: AsyncClient, sandbox_config: SandboxConfig
    ) -> None:
        create = await client.post(
            "/conversations",
            json={
                "title": "cb-route",
                "sandbox_config_id": str(sandbox_config.id),
                "llm_model": "claude-sonnet-4",
                "agent_kind": "openhands",
                "trigger": "manual",
            },
        )
        conv_id = create.json()["id"]
        resp = await client.patch(
            f"/conversations/{conv_id}",
            json={"event_callbacks": [_logging_callback_json("warning")]},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["event_callbacks"]) == 1
        assert body["event_callbacks"][0]["level"] == "warning"

    async def test_template_create_with_default_callbacks(self, client: AsyncClient) -> None:
        payload = {
            "name": "cb-template-route",
            "agent_config": {"agent": "CodeActAgent"},
            "conversation_config": {"max_iterations": 100},
            "default_callbacks": [_logging_callback_json("debug")],
        }
        resp = await client.post("/conversation-templates", json=payload)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert len(body["default_callbacks"]) == 1
        assert body["default_callbacks"][0]["kind"] == "LoggingCallback"
        assert body["default_callbacks"][0]["level"] == "debug"
