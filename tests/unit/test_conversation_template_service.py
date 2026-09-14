"""Unit tests for the conversation template service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal

from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateBatchCreate,
    ConversationTemplateBatchDelete,
    ConversationTemplateBatchUpdate,
    ConversationTemplateCreate,
    ConversationTemplateSearchFilter,
    ConversationTemplateUpdate,
)
from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateUpdate as _ConversationTemplateUpdate,
)
from openhands.ev2.conversation_template.conversation_template_service import (
    BatchPermissionDeniedError,
    ConversationTemplateNotFoundError,
    ConversationTemplatePermissionScopeError,
    ConversationTemplateService,
    ReferencedEntityNotFoundError,
)
from openhands.ev2.llm.llm_models import StoredLLM, StoredProviderConnection
from openhands.ev2.security.security_models import Action, CreatorPermission, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL, NONE


async def _stored_llm(session: AsyncSession, creator_id: uuid.UUID) -> StoredLLM:
    connection = StoredProviderConnection(
        creator_id=creator_id,
        display_name="anthropic",
        provider="anthropic",
        base_url="https://api.anthropic.com",
        api_key=None,
        enable_proxy=False,
    )
    session.add(connection)
    await session.flush()
    llm = StoredLLM(
        creator_id=creator_id,
        provider_connection_id=connection.id,
        display_name="claude",
        model="anthropic/claude-sonnet-4",
        config={},
    )
    session.add(llm)
    await session.flush()
    return llm


def _create_payload(**overrides: object) -> ConversationTemplateCreate:
    data: dict[str, object] = {
        "name": "default",
        "agent_kind": "openhands",
        "llm_id": None,
        "mcp_server_config_ids": [],
        "secret_provider_ids": [],
        "static_secret_ids": [],
        "agent_config": {"tools": ["terminal"]},
        "conversation_config": {"max_iterations": 100},
        "system_message_suffix": "suffix",
        "default_callbacks": [],
    }
    data.update(overrides)
    return ConversationTemplateCreate(**data)  # type: ignore[arg-type]


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="tpl-owner@example.com", username="tpl-owner")


@pytest.fixture
def service(session: AsyncSession) -> ConversationTemplateService:
    return ConversationTemplateService(session, ALL)


class TestCreate:
    async def test_create_happy_path(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        template = await service.create(_create_payload(name="t1"), creator_id=owner.id)
        assert template.id is not None
        assert template.creator_id == owner.id
        assert template.name == "t1"
        assert template.agent_kind == "openhands"
        assert template.agent_config == {"tools": ["terminal"]}
        assert template.conversation_config == {"max_iterations": 100}
        assert template.system_message_suffix == "suffix"

    async def test_create_with_llm(
        self, service: ConversationTemplateService, session: AsyncSession, owner: User
    ) -> None:
        llm = await _stored_llm(session, owner.id)
        template = await service.create(
            _create_payload(name="with-llm", llm_id=llm.id), creator_id=owner.id
        )
        assert template.llm_id == llm.id

    async def test_create_missing_llm_rejects(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        with pytest.raises(ReferencedEntityNotFoundError):
            await service.create(
                _create_payload(name="bad-llm", llm_id=uuid.uuid4()),
                creator_id=owner.id,
            )

    async def test_create_scope_error(self, session: AsyncSession, owner: User) -> None:
        # A denied perm filter blocks create in the service layer.
        service = ConversationTemplateService(session, NONE)
        with pytest.raises(ConversationTemplatePermissionScopeError):
            await service.create(_create_payload(name="x"), creator_id=owner.id)


class TestReadAndSearch:
    async def test_get_and_get_many(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        a = await service.create(_create_payload(name="a"), creator_id=owner.id)
        b = await service.create(_create_payload(name="b"), creator_id=owner.id)
        got = await service.get(a.id)
        assert got.name == "a"
        many = await service.get_many([a.id, b.id, uuid.uuid4()])
        assert [m.id if m else None for m in many] == [a.id, b.id, None]

    async def test_get_missing_raises(self, service: ConversationTemplateService) -> None:
        with pytest.raises(ConversationTemplateNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_many_empty_list(self, service: ConversationTemplateService) -> None:
        assert await service.get_many([]) == []

    async def test_search_with_cursor(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        """Cursor pagination walks all rows without overlap, id order agnostic."""
        first = await service.create(_create_payload(name="cursor-1"), creator_id=owner.id)
        second = await service.create(_create_payload(name="cursor-2"), creator_id=owner.id)
        rows, next_cursor = await service.search(limit=1)
        assert len(rows) == 1
        assert next_cursor is not None
        seen = {r.id for r in rows}
        rows, next_cursor = await service.search(cursor=next_cursor, limit=10)
        assert len(rows) == 1
        assert next_cursor is None
        assert not {r.id for r in rows} & seen  # pages never overlap.
        assert seen | {r.id for r in rows} == {first.id, second.id}
        # Cursor keyed off a row id also resumes past it.
        rows, _ = await service.search(cursor=seen.pop(), limit=10)
        assert len(rows) == 1

    async def test_search_and_count(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        await service.create(_create_payload(name="alpha"), creator_id=owner.id)
        await service.create(_create_payload(name="beta"), creator_id=owner.id)
        rows, next_cursor = await service.search(limit=10)
        assert len(rows) == 2
        assert next_cursor is None

        filt = ConversationTemplateSearchFilter(name__contains="alp")
        rows, _ = await service.search(search_filter=filt)
        assert len(rows) == 1
        assert rows[0].name == "alpha"

        assert await service.count() == 2
        assert await service.count(search_filter=filt) == 1


class TestUpdateAndDelete:
    async def test_partial_update(self, service: ConversationTemplateService, owner: User) -> None:
        template = await service.create(_create_payload(name="orig"), creator_id=owner.id)
        updated = await service.update(
            template.id,
            ConversationTemplateUpdate(name="changed", system_message_suffix=None),
        )
        assert updated.name == "changed"
        assert updated.system_message_suffix is None
        # Unset fields unchanged.
        assert updated.conversation_config == {"max_iterations": 100}

    async def test_update_llm_validation(
        self, service: ConversationTemplateService, session: AsyncSession, owner: User
    ) -> None:
        template = await service.create(_create_payload(name="x"), creator_id=owner.id)
        with pytest.raises(ReferencedEntityNotFoundError):
            await service.update(template.id, ConversationTemplateUpdate(llm_id=uuid.uuid4()))
        llm = await _stored_llm(session, owner.id)
        updated = await service.update(template.id, ConversationTemplateUpdate(llm_id=llm.id))
        assert updated.llm_id == llm.id

    async def test_update_missing_raises(self, service: ConversationTemplateService) -> None:
        with pytest.raises(ConversationTemplateNotFoundError):
            await service.update(uuid.uuid4(), ConversationTemplateUpdate(name="x"))

    async def test_delete(self, service: ConversationTemplateService, owner: User) -> None:
        template = await service.create(_create_payload(name="gone"), creator_id=owner.id)
        await service.delete(template.id)
        with pytest.raises(ConversationTemplateNotFoundError):
            await service.get(template.id)


class TestBatch:
    async def test_batch_mixed_apply(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        perm_filters = {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL}
        template = await service.create(_create_payload(name="orig"), creator_id=owner.id)
        results = await service.apply_batch(
            [
                ConversationTemplateBatchCreate(data=_create_payload(name="created")),
                ConversationTemplateBatchUpdate(
                    id=template.id, data=ConversationTemplateUpdate(name="patched")
                ),
                ConversationTemplateBatchDelete(id=template.id),
            ],
            perm_filters,
            creator_id=owner.id,
        )
        assert results[0].name == "created"
        assert results[1].name == "patched"
        assert results[2] is None

    async def test_batch_denies_when_action_not_granted(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        perm_filters = {
            Action.CREATE: ALL,
            Action.UPDATE: None,
            Action.DELETE: ALL,
        }
        a = await service.create(_create_payload(name="a"), creator_id=owner.id)
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [
                    ConversationTemplateBatchUpdate(
                        id=a.id, data=ConversationTemplateUpdate(name="x")
                    )
                ],
                perm_filters,
                creator_id=owner.id,
            )

    async def test_batch_delete_denied(
        self, service: ConversationTemplateService, owner: User
    ) -> None:
        perm_filters = {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: None}
        a = await service.create(_create_payload(name="a"), creator_id=owner.id)
        with pytest.raises(BatchPermissionDeniedError):
            await service.apply_batch(
                [ConversationTemplateBatchDelete(id=a.id)],
                perm_filters,
                creator_id=owner.id,
            )


class TestCreatorScope:
    async def test_creator_permission_scopes_to_own_rows(
        self, session: AsyncSession, owner: User
    ) -> None:
        """The service's perm filter scopes reads to the principal's own rows.

        A template created by ``other`` is invisible to a principal whose
        ``CreatorPermission`` denies non-matching rows (fail-closed 404), and
        becomes visible once the same policy grants non-matching rows — the
        grant-role USE path from issue #132.
        """
        other = await make_principal(session, email="tpl-other@example.com", username="tpl-other")
        owner_service = ConversationTemplateService(session, ALL)
        template = await owner_service.create(_create_payload(name="mine"), creator_id=other.id)

        denied = CreatorPermission(on_match=Permitted(), on_create=Permitted()).to_search_filter(
            owner.id, Action.READ
        )
        denied_service = ConversationTemplateService(session, denied)
        with pytest.raises(ConversationTemplateNotFoundError):
            await denied_service.get(template.id)
        rows, _ = await denied_service.search()
        assert rows == []

        # on_mismatch=Permitted(): owner can now READ/SEARCH the row created by
        # other — the non-creator grant-role path.
        granted = CreatorPermission(
            on_match=Permitted(), on_mismatch=Permitted(), on_create=Permitted()
        ).to_search_filter(owner.id, Action.READ)
        granted_service = ConversationTemplateService(session, granted)
        assert (await granted_service.get(template.id)).id == template.id
        rows, _ = await granted_service.search()
        assert [r.id for r in rows] == [template.id]


class TestUpdateSchemaValidation:
    def test_update_name_none_is_allowed(self) -> None:
        # Not passing `name` means the field is untouched; the validator must
        # not reject the implicit None.
        payload = _ConversationTemplateUpdate()
        assert payload.name is None

    def test_update_blank_name_rejected(self) -> None:
        # When the caller does set `name`, it must be non-blank.
        with pytest.raises(ValueError):
            _ConversationTemplateUpdate(name="   ")
