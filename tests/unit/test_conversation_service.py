"""Unit tests for the conversation service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal, make_sandbox_config

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import (
    ConversationBatchCreate,
    ConversationBatchDelete,
    ConversationBatchUpdate,
    ConversationCreate,
    ConversationSearchFilter,
    ConversationUpdate,
)
from openhands.ev2.conversation.conversation_security import ConversationAccessFilter
from openhands.ev2.conversation.conversation_service import (
    BatchPermissionDeniedError,
    ConversationNotFoundError,
    ConversationPermissionScopeError,
    ConversationService,
)
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL, NONE


def _create_payload(sandbox_config_id: uuid.UUID, **overrides: object) -> ConversationCreate:
    data: dict[str, object] = {
        "title": "test conversation",
        "sandbox_config_id": sandbox_config_id,
        "llm_model": "claude-sonnet-4",
        "agent_kind": "openhands",
        "selected_repository": "org/repo",
        "selected_branch": "main",
        "trigger": "manual",
    }
    data.update(overrides)
    return ConversationCreate(**data)  # type: ignore[arg-type]


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="owner@example.com", username="owner")


@pytest.fixture
async def sandbox_config(session: AsyncSession, owner: User) -> SandboxConfig:
    return await make_sandbox_config(session, creator_id=owner.id)


@pytest.fixture
def service(session: AsyncSession) -> ConversationService:
    return ConversationService(session, ALL)


class TestCreateConversation:
    async def test_create_defaults_metrics_to_zero(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        conversation = await service.create(_create_payload(sandbox_config.id))
        assert conversation.id is not None
        assert conversation.title == "test conversation"
        assert conversation.sandbox_config_id == sandbox_config.id
        assert conversation.accumulated_cost == 0.0
        assert conversation.prompt_tokens == 0
        assert conversation.completion_tokens == 0
        assert conversation.total_tokens == 0
        assert conversation.created_at is not None
        assert conversation.updated_at is not None
        # The backing config relationship resolves for in-memory scope checks.
        assert conversation.sandbox_config.creator_id == sandbox_config.creator_id

    async def test_create_outside_scope_denied(
        self, session: AsyncSession, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, NONE)
        with pytest.raises(ConversationPermissionScopeError):
            await service.create(_create_payload(sandbox_config.id))

    async def test_create_scoped_to_other_user_denied(
        self, session: AsyncSession, owner: User, sandbox_config: SandboxConfig
    ) -> None:
        # A ConversationAccessFilter keyed on another user cannot match the
        # prospective row: its sandbox_config relationship is not loaded yet.
        other = uuid.uuid4()
        assert other != owner.id
        service = ConversationService(
            session, ConversationAccessFilter[Conversation](user_id=other)
        )
        with pytest.raises(ConversationPermissionScopeError):
            await service.create(_create_payload(sandbox_config.id))


class TestGetConversation:
    async def test_get_existing(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        created = await service.create(_create_payload(sandbox_config.id))
        fetched = await service.get(created.id)
        assert fetched.id == created.id

    async def test_get_missing_raises(self, service: ConversationService) -> None:
        with pytest.raises(ConversationNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_out_of_scope_raises(
        self, session: AsyncSession, owner: User, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, ALL)
        created = await service.create(_create_payload(sandbox_config.id))
        scoped = ConversationService(
            session, ConversationAccessFilter[Conversation](user_id=uuid.uuid4())
        )
        with pytest.raises(ConversationNotFoundError):
            await scoped.get(created.id)


class TestGetMany:
    async def test_get_many_positionally_aligned(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        first = await service.create(_create_payload(sandbox_config.id, title="first"))
        second = await service.create(_create_payload(sandbox_config.id, title="second"))
        missing = uuid.uuid4()
        results = await service.get_many([second.id, missing, first.id, second.id])
        assert [r.id if r is not None else None for r in results] == [
            second.id,
            None,
            first.id,
            second.id,
        ]

    async def test_get_many_empty(self, service: ConversationService) -> None:
        assert await service.get_many([]) == []


class TestSearchConversations:
    async def test_search_scoped_by_perm_filter(
        self, session: AsyncSession, owner: User, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, ALL)
        own = await service.create(_create_payload(sandbox_config.id, title="own"))
        other_user = await make_principal(session, email="other@example.com", username="other")
        other_config = await make_sandbox_config(session, creator_id=other_user.id)
        foreign = await service.create(_create_payload(other_config.id, title="foreign"))

        scoped = ConversationService(
            session, ConversationAccessFilter[Conversation](user_id=owner.id)
        )
        found, next_cursor = await scoped.search_conversations()
        assert next_cursor is None
        assert {c.id for c in found} == {own.id}
        assert foreign.id not in {c.id for c in found}

        denied = ConversationService(session, NONE)
        found, _ = await denied.search_conversations()
        assert found == []

    async def test_search_filter_narrows_results(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        await service.create(_create_payload(sandbox_config.id, title="alpha"))
        beta = await service.create(
            _create_payload(sandbox_config.id, title="beta", trigger="webhook")
        )
        found, _ = await service.search_conversations(
            search_filter=ConversationSearchFilter(title__contains="BET")
        )
        assert [c.id for c in found] == [beta.id]
        found, _ = await service.search_conversations(
            search_filter=ConversationSearchFilter(trigger__eq="webhook")
        )
        assert [c.id for c in found] == [beta.id]
        found, _ = await service.search_conversations(
            search_filter=ConversationSearchFilter(sandbox_config_id__eq=uuid.uuid4())
        )
        assert found == []

    async def test_search_paginates_with_cursor(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        created = [
            await service.create(_create_payload(sandbox_config.id, title=f"c{i}"))
            for i in range(3)
        ]
        page1, cursor = await service.search_conversations(limit=2)
        assert cursor is not None
        assert len(page1) == 2
        page2, cursor2 = await service.search_conversations(cursor=cursor, limit=2)
        assert cursor2 is None
        assert len(page2) == 1
        # Pages are disjoint and together cover every row.
        assert {c.id for c in page1} | {c.id for c in page2} == {c.id for c in created}


class TestUpdateConversation:
    async def test_update_metrics_and_fields(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        created = await service.create(_create_payload(sandbox_config.id))
        updated = await service.update(
            created.id,
            ConversationUpdate(
                title="renamed",
                accumulated_cost=1.25,
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
            ),
        )
        assert updated.title == "renamed"
        assert updated.accumulated_cost == 1.25
        assert updated.prompt_tokens == 100
        assert updated.completion_tokens == 50
        assert updated.total_tokens == 150
        # Unset fields are left unchanged.
        assert updated.trigger == "manual"
        assert updated.sandbox_config_id == sandbox_config.id

    async def test_update_missing_raises(self, service: ConversationService) -> None:
        with pytest.raises(ConversationNotFoundError):
            await service.update(uuid.uuid4(), ConversationUpdate(title="x"))

    async def test_update_rejects_negative_metrics(self) -> None:
        with pytest.raises(ValueError):
            ConversationUpdate(prompt_tokens=-1)


class TestConversationUpdateSchema:
    def test_title_none_passthrough(self) -> None:
        assert ConversationUpdate(title=None).title is None

    def test_title_blank_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConversationUpdate(title="   ")

    def test_title_stripped(self) -> None:
        assert ConversationUpdate(title="  x  ").title == "x"


class TestDeleteConversation:
    async def test_delete(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        created = await service.create(_create_payload(sandbox_config.id))
        await service.delete(created.id)
        with pytest.raises(ConversationNotFoundError):
            await service.get(created.id)

    async def test_delete_missing_raises(self, service: ConversationService) -> None:
        with pytest.raises(ConversationNotFoundError):
            await service.delete(uuid.uuid4())


class TestBatch:
    async def test_apply_batch_mixed(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        existing = await service.create(_create_payload(sandbox_config.id, title="existing"))
        doomed = await service.create(_create_payload(sandbox_config.id, title="doomed"))
        results = await service.apply_batch(
            [
                ConversationBatchCreate(data=_create_payload(sandbox_config.id, title="new")),
                ConversationBatchUpdate(id=existing.id, data=ConversationUpdate(title="renamed")),
                ConversationBatchDelete(id=doomed.id),
            ],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert len(results) == 3
        assert results[0] is not None and results[0].title == "new"
        assert results[1] is not None and results[1].title == "renamed"
        assert results[2] is None
        with pytest.raises(ConversationNotFoundError):
            await service.get(doomed.id)

    async def test_apply_batch_denies_ungranted_action(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        # A None filter for the operation's action denies the whole batch.
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [ConversationBatchCreate(data=_create_payload(sandbox_config.id))],
                {Action.CREATE: None, Action.UPDATE: None, Action.DELETE: None},
            )

    async def test_apply_batch_denies_missing_action_grant(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [ConversationBatchDelete(id=uuid.uuid4())],
                {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: None},
            )

    async def test_apply_batch_update_denied(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [ConversationBatchUpdate(id=uuid.uuid4(), data=ConversationUpdate(title="x"))],
                {Action.CREATE: ALL, Action.UPDATE: None, Action.DELETE: ALL},
            )

    async def test_apply_batch_create_outside_scope(
        self, service: ConversationService, sandbox_config: SandboxConfig
    ) -> None:
        with pytest.raises(ConversationPermissionScopeError):
            await service.apply_batch(
                [ConversationBatchCreate(data=_create_payload(sandbox_config.id))],
                {Action.CREATE: NONE, Action.UPDATE: ALL, Action.DELETE: ALL},
            )

    async def test_apply_batch_update_missing_raises(self, service: ConversationService) -> None:
        with pytest.raises(ConversationNotFoundError):
            await service.apply_batch(
                [ConversationBatchUpdate(id=uuid.uuid4(), data=ConversationUpdate(title="x"))],
                {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
            )


class TestCount:
    async def test_count_scoped(
        self, session: AsyncSession, owner: User, sandbox_config: SandboxConfig
    ) -> None:
        service = ConversationService(session, ALL)
        assert await service.count() == 0
        await service.create(_create_payload(sandbox_config.id))
        assert await service.count() == 1
        assert (
            await service.count(search_filter=ConversationSearchFilter(title__contains="zzz")) == 0
        )
        scoped = ConversationService(
            session, ConversationAccessFilter[Conversation](user_id=uuid.uuid4())
        )
        assert await scoped.count() == 0
