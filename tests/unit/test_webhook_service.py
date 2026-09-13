"""Service-level tests for the webhook ingestion authorization branches.

Route-level guards collapse deny-filtered roles to ``None`` (403); the
service still re-checks ``matches`` on the candidate/existing row so exotic
(non-degenerate) deny filters fail closed too. These tests exercise those
branches directly with a custom deny/filter predicate and lightweight
ConversationInfo stubs (avoiding the SDK imports here).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal, make_sandbox_config

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.util.search_filter import SearchFilter, SqlCondition
from openhands.ev2.webhook.webhook_service import (
    WebhookConversationNotFoundError,
    WebhookSandboxNotFoundError,
    WebhookService,
)


class _Deny(SearchFilter[Conversation]):
    """A filter that matches nothing (in-memory predicate always False)."""

    def matches(self, item: Conversation) -> bool:
        return False

    def sql_condition(self) -> SqlCondition:
        return None


async def _sandbox_config(session: AsyncSession) -> SandboxConfig:
    """A config owned by a real user (the sandbox_templates FK needs one)."""
    user = await make_principal(
        session,
        email=f"s-{uuid.uuid4().hex[:8]}@example.com",
        username=f"s-{uuid.uuid4().hex[:8]}",
    )
    return await make_sandbox_config(session, creator_id=user.id)


def _info(conversation_id: uuid.UUID) -> Any:
    """A minimal ConversationInfo-like stub (SDK ConversationInfo untouched)."""
    info = type("Info", (), {})()
    info.id = conversation_id
    info.title = None
    info.agent = None
    info.stats = None
    info.execution_status = None
    return info


async def _conversation(session: AsyncSession, config_id: uuid.UUID) -> Conversation:
    conversation = Conversation(
        title="existing",
        sandbox_config_id=config_id,
        llm_model="m",
        agent_kind="openhands",
        trigger="manual",
    )
    session.add(conversation)
    await session.flush()
    return conversation


class TestUpsertConversationScope:
    async def test_create_filter_mismatch(self, session: AsyncSession) -> None:
        """A candidate denied by the create filter fails closed."""
        config = await _sandbox_config(session)
        service = WebhookService(session, config.id, _Deny(), None, None)
        with pytest.raises(WebhookConversationNotFoundError):
            await service.upsert_conversation(_info(uuid.uuid4()))

    async def test_update_filter_mismatch(self, session: AsyncSession) -> None:
        """An existing row denied by the update filter fails closed."""
        config = await _sandbox_config(session)
        conversation = await _conversation(session, config.id)
        service = WebhookService(session, config.id, _Deny(), _Deny(), None)
        with pytest.raises(WebhookConversationNotFoundError):
            await service.upsert_conversation(_info(conversation.id))

    async def test_unknown_config(self, session: AsyncSession) -> None:
        service = WebhookService(session, uuid.uuid4(), None, None, None)
        with pytest.raises(WebhookSandboxNotFoundError):
            await service.upsert_conversation(_info(uuid.uuid4()))


class TestIngestEventsScope:
    async def test_event_filter_mismatch(self, session: AsyncSession) -> None:
        """A candidate denied by the event create filter fails closed."""
        config = await _sandbox_config(session)
        conversation = await _conversation(session, config.id)
        service = WebhookService(session, config.id, None, None, _Deny())
        with pytest.raises(WebhookConversationNotFoundError):
            await service.ingest_events(conversation.id, [])

    async def test_unknown_config(self, session: AsyncSession) -> None:
        service = WebhookService(session, uuid.uuid4(), None, None, None)
        with pytest.raises(WebhookSandboxNotFoundError):
            await service.ingest_events(uuid.uuid4(), [])
