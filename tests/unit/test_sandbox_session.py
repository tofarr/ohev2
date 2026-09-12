"""Unit tests for the sandbox session-key ingestion auth (sandbox_session.py)."""

from __future__ import annotations

import hashlib
import uuid

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import (
    make_principal as _make_principal,
)
from tests.unit._auth_helpers import (
    make_sandbox_config as _make_sandbox_config,
)

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.event.event_models import Event
from openhands.ev2.sandbox.sandbox_session import (
    SandboxConversationScopeFilter,
    SandboxEventScopeFilter,
    depends_sandbox_config,
    hash_session_api_key,
    resolve_sandbox_config_by_session_key,
    sandbox_scope_filter,
)
from openhands.ev2.user.user_models import User


@pytest_asyncio.fixture
async def principal_id(session: AsyncSession) -> uuid.UUID:
    """A real user id to satisfy the sandbox config creator FK."""
    user = await _make_principal(session, email="owner@example.com", username="owner")
    return user.id


def _conversation(conversation_id: uuid.UUID, sandbox_config_id: uuid.UUID) -> Conversation:
    conversation = Conversation(
        title="t",
        sandbox_config_id=sandbox_config_id,
        llm_model="m",
        agent_kind="openhands",
        trigger="webhook",
    )
    conversation.id = conversation_id
    return conversation


class TestHashSessionApiKey:
    def test_deterministic_sha256_hex(self) -> None:
        assert hash_session_api_key("abc") == hashlib.sha256(b"abc").hexdigest()

    def test_distinct_keys_distinct_hashes(self) -> None:
        assert hash_session_api_key("a") != hash_session_api_key("b")


class TestResolveSandboxConfig:
    async def test_resolves_by_plaintext_key(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config = await _make_sandbox_config(
            session, creator_id=principal_id, session_key="k-resolve"
        )
        resolved = await resolve_sandbox_config_by_session_key(session, "k-resolve")
        assert resolved is not None
        assert resolved.id == config.id

    async def test_unknown_key_returns_none(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        await _make_sandbox_config(session, creator_id=principal_id)
        assert await resolve_sandbox_config_by_session_key(session, "nope") is None


class TestDependsSandboxConfig:
    async def test_valid_key_resolves_config(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config = await _make_sandbox_config(session, creator_id=principal_id, session_key="k-dep")
        resolved = await depends_sandbox_config(session, "k-dep")
        assert resolved.id == config.id

    async def test_missing_key_401(self, session: AsyncSession) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await depends_sandbox_config(session, None)
        assert exc_info.value.status_code == 401

    async def test_unknown_key_401(self, session: AsyncSession) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await depends_sandbox_config(session, "unknown")
        assert exc_info.value.status_code == 401


class TestScopeFilters:
    async def test_conversation_scope_matches(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config_a = await _make_sandbox_config(session, creator_id=principal_id)
        config_b = await _make_sandbox_config(session, creator_id=principal_id)
        scope = SandboxConversationScopeFilter(sandbox_config_id=config_a.id)
        assert scope.matches(_conversation(uuid.uuid4(), config_a.id))
        assert not scope.matches(_conversation(uuid.uuid4(), config_b.id))

    async def test_conversation_scope_sql(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config_a = await _make_sandbox_config(session, creator_id=principal_id)
        config_b = await _make_sandbox_config(session, creator_id=principal_id)
        conv_a = _conversation(uuid.uuid4(), config_a.id)
        conv_b = _conversation(uuid.uuid4(), config_b.id)
        session.add_all([conv_a, conv_b])
        await session.flush()
        scope = SandboxConversationScopeFilter(sandbox_config_id=config_a.id)
        rows = list((await session.execute(scope.filter_sql(select(Conversation)))).scalars().all())
        assert [c.id for c in rows] == [conv_a.id]

    async def test_event_scope_matches_and_sql(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config_a = await _make_sandbox_config(session, creator_id=principal_id)
        config_b = await _make_sandbox_config(session, creator_id=principal_id)
        conv_a = _conversation(uuid.uuid4(), config_a.id)
        conv_b = _conversation(uuid.uuid4(), config_b.id)
        session.add_all([conv_a, conv_b])
        await session.flush()
        event_a = Event(conversation_id=conv_a.id, kind="k", body={}, size_bytes=0)
        event_b = Event(conversation_id=conv_b.id, kind="k", body={}, size_bytes=0)
        session.add_all([event_a, event_b])
        await session.flush()

        scope = SandboxEventScopeFilter(
            sandbox_config_id=config_a.id, conversation_ids=frozenset({conv_a.id})
        )
        assert scope.matches(event_a)
        assert not scope.matches(event_b)
        rows = list((await session.execute(scope.filter_sql(select(Event)))).scalars().all())
        assert [e.id for e in rows] == [event_a.id]


class TestSandboxScopeFilterFactory:
    async def test_conversation_model(self, session: AsyncSession, principal_id: uuid.UUID) -> None:
        config = await _make_sandbox_config(session, creator_id=principal_id)
        scope = await sandbox_scope_filter(session, Conversation, config.id)
        assert isinstance(scope, SandboxConversationScopeFilter)

    async def test_event_model_collects_conversation_ids(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config = await _make_sandbox_config(session, creator_id=principal_id)
        conv = _conversation(uuid.uuid4(), config.id)
        session.add(conv)
        await session.flush()
        scope = await sandbox_scope_filter(session, Event, config.id)
        assert isinstance(scope, SandboxEventScopeFilter)
        assert scope.conversation_ids == frozenset({conv.id})

    async def test_unsupported_model_raises(
        self, session: AsyncSession, principal_id: uuid.UUID
    ) -> None:
        config = await _make_sandbox_config(session, creator_id=principal_id)
        with pytest.raises(ValueError, match="No sandbox scope"):
            await sandbox_scope_filter(session, User, config.id)
