"""Unit tests for the event callback feature (issue #134).

These tests use the same hermetic PostgreSQL + FastAPI ASGI client fixtures as
the rest of the suite (see ``conftest.py``). They cover:

* the service layer (create / get / get_many / search / update / delete /
  count / batch) including the exactly-one-link invariant
* the HTTP routes (governed CRUD + batch + count) including the role-schema
  parity for ``event_callback_permission``

The dispatch logic (invoking the processor, updating merged result state) is
issue #4 and is intentionally not exercised here — the CRUD resource only
persists and retrieves the polymorphic ``processor`` and the merged result
columns.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal, make_sandbox_config

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.conversation.conversation_schemas import ConversationCreate
from openhands.ev2.conversation.conversation_service import ConversationService
from openhands.ev2.conversation_template.conversation_template_models import (
    ConversationTemplate,
)
from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateCreate,
)
from openhands.ev2.conversation_template.conversation_template_service import (
    ConversationTemplateService,
)
from openhands.ev2.event_callback.event_callback_models import (
    EventCallbackProcessor,
    LoggingCallbackProcessor,
)
from openhands.ev2.event_callback.event_callback_schemas import (
    EventCallbackCreate,
    EventCallbackUpdate,
)
from openhands.ev2.event_callback.event_callback_service import (
    EventCallbackLinkInvariantError,
    EventCallbackNotFoundError,
    EventCallbackService,
)
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.security.security_models import CreatorPermission, Permitted
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL

pytestmark = pytest.mark.asyncio


def _processor(level: str = "info") -> LoggingCallbackProcessor:
    return LoggingCallbackProcessor(level=level)


def _processor_json(level: str = "info") -> dict[str, Any]:
    return _processor(level).model_dump(mode="json")


def _conv_payload(conversation_id: uuid.UUID, event_kind: str = "MessageEvent") -> dict[str, Any]:
    return {
        "event_kind": event_kind,
        "processor": _processor_json(),
        "conversation_id": str(conversation_id),
    }


def _tmpl_payload(template_id: uuid.UUID, event_kind: str = "MessageEvent") -> dict[str, Any]:
    return {
        "event_kind": event_kind,
        "processor": _processor_json(),
        "conversation_template_id": str(template_id),
    }


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="cb-owner@example.com", username="cb-owner")


@pytest.fixture
async def sandbox_config(session: AsyncSession, owner: User) -> SandboxConfig:
    return await make_sandbox_config(session, creator_id=owner.id)


@pytest.fixture
async def conversation(session: AsyncSession, sandbox_config: SandboxConfig) -> Conversation:
    service = ConversationService(session, ALL)
    return await service.create(
        ConversationCreate(
            title="cb-test",
            sandbox_config_id=sandbox_config.id,
            llm_model="claude-sonnet-4",
            agent_kind="openhands",
            selected_repository=None,
            selected_branch=None,
            trigger="manual",
        )
    )


@pytest.fixture
async def conversation_template(session: AsyncSession, owner: User) -> ConversationTemplate:
    service = ConversationTemplateService(session, ALL)
    return await service.create(
        ConversationTemplateCreate(
            name="cb-test-template",
            agent_config={"agent": "CodeActAgent"},
            conversation_config={"max_iterations": 100},
        ),
        creator_id=owner.id,
    )


# --------------------------------------------------------------------------- #
# Processor round-trip
# --------------------------------------------------------------------------- #


class TestProcessorRoundTrip:
    async def test_processor_serializes_and_deserializes(self) -> None:
        p = LoggingCallbackProcessor(level="debug")
        data = p.model_dump(mode="json")
        assert data["kind"] == "LoggingCallbackProcessor"
        round_tripped = EventCallbackProcessor.model_validate(data)
        assert isinstance(round_tripped, LoggingCallbackProcessor)
        assert round_tripped.level == "debug"


# --------------------------------------------------------------------------- #
# Service layer
# --------------------------------------------------------------------------- #


class TestEventCallbackService:
    async def test_create_and_get_conversation_linked(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="MessageEvent",
                processor=_processor(),
                conversation_id=conversation.id,
            ),
            creator_id=owner.id,
        )
        assert callback.id is not None
        assert callback.creator_id == owner.id
        assert callback.conversation_id == conversation.id
        assert callback.conversation_template_id is None
        assert callback.status == "READY"
        assert isinstance(callback.processor, LoggingCallbackProcessor)

        fetched = await service.get(callback.id)
        assert fetched.id == callback.id

    async def test_create_and_get_template_linked(
        self,
        session: AsyncSession,
        conversation_template: ConversationTemplate,
        owner: User,
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="MessageEvent",
                processor=_processor(),
                conversation_template_id=conversation_template.id,
            ),
            creator_id=owner.id,
        )
        assert callback.conversation_id is None
        assert callback.conversation_template_id == conversation_template.id

    async def test_create_rejects_both_links(self) -> None:
        with pytest.raises(ValueError, match="Exactly one"):
            EventCallbackCreate(
                event_kind="MessageEvent",
                processor=_processor(),
                conversation_id=uuid.uuid4(),
                conversation_template_id=uuid.uuid4(),
            )

    async def test_create_rejects_neither_link(self) -> None:
        with pytest.raises(ValueError, match="Exactly one"):
            EventCallbackCreate(
                event_kind="MessageEvent",
                processor=_processor(),
            )

    async def test_get_missing_returns_not_found(self, session: AsyncSession) -> None:
        service = EventCallbackService(session, ALL)
        with pytest.raises(EventCallbackNotFoundError):
            await service.get(uuid.uuid4())

    async def test_get_many_returns_aligned_with_ids(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        c1 = await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        c2 = await service.create(
            EventCallbackCreate(
                event_kind="B", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        missing = uuid.uuid4()
        results = await service.get_many([c2.id, missing, c1.id])
        assert results[0] is not None and results[0].id == c2.id
        assert results[1] is None
        assert results[2] is not None and results[2].id == c1.id

    async def test_get_many_empty_returns_empty(self, session: AsyncSession) -> None:
        service = EventCallbackService(session, ALL)
        assert await service.get_many([]) == []

    async def test_search_paginates_by_cursor(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        for i in range(5):
            await service.create(
                EventCallbackCreate(
                    event_kind=f"kind_{i}",
                    processor=_processor(),
                    conversation_id=conversation.id,
                ),
                creator_id=owner.id,
            )
        rows, next_cursor = await service.search(limit=2)
        assert len(rows) == 2
        assert next_cursor is not None
        rows2, _ = await service.search(cursor=next_cursor, limit=2)
        assert len(rows2) == 2
        assert rows2[0].id > rows[-1].id

    async def test_count(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        assert await service.count() == 0
        await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        assert await service.count() == 1

    async def test_update_changes_fields(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        updated = await service.update(
            callback.id,
            EventCallbackUpdate(event_kind="B", status="SUCCESS", detail="ran ok"),
        )
        assert updated.event_kind == "B"
        assert updated.status == "SUCCESS"
        assert updated.detail == "ran ok"

    async def test_update_swaps_link_from_conversation_to_template(
        self,
        session: AsyncSession,
        conversation: Conversation,
        conversation_template: ConversationTemplate,
        owner: User,
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        updated = await service.update(
            callback.id,
            EventCallbackUpdate(
                conversation_id=None,
                conversation_template_id=conversation_template.id,
            ),
        )
        assert updated.conversation_id is None
        assert updated.conversation_template_id == conversation_template.id

    async def test_update_clearing_both_links_raises(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        with pytest.raises(EventCallbackLinkInvariantError):
            await service.update(
                callback.id,
                EventCallbackUpdate(conversation_id=None),
            )

    async def test_update_missing_returns_not_found(self, session: AsyncSession) -> None:
        service = EventCallbackService(session, ALL)
        with pytest.raises(EventCallbackNotFoundError):
            await service.update(uuid.uuid4(), EventCallbackUpdate(event_kind="B"))

    async def test_delete_removes(
        self, session: AsyncSession, conversation: Conversation, owner: User
    ) -> None:
        service = EventCallbackService(session, ALL)
        callback = await service.create(
            EventCallbackCreate(
                event_kind="A", processor=_processor(), conversation_id=conversation.id
            ),
            creator_id=owner.id,
        )
        await service.delete(callback.id)
        with pytest.raises(EventCallbackNotFoundError):
            await service.get(callback.id)

    async def test_delete_missing_returns_not_found(self, session: AsyncSession) -> None:
        service = EventCallbackService(session, ALL)
        with pytest.raises(EventCallbackNotFoundError):
            await service.delete(uuid.uuid4())


# --------------------------------------------------------------------------- #
# HTTP routes (client is authenticated as the test admin principal — Permitted
# on all entity columns including event_callback_permission)
# --------------------------------------------------------------------------- #


class TestEventCallbackRoutes:
    async def test_create_and_get_conversation_linked(
        self, client: AsyncClient, conversation: Conversation
    ) -> None:
        resp = await client.post("/event-callbacks", json=_conv_payload(conversation.id))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["conversation_id"] == str(conversation.id)
        assert body["conversation_template_id"] is None
        assert body["status"] == "READY"
        assert body["processor"]["kind"] == "LoggingCallbackProcessor"

        resp = await client.get(f"/event-callbacks/{body['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == body["id"]

    async def test_create_template_linked(
        self, client: AsyncClient, conversation_template: ConversationTemplate
    ) -> None:
        resp = await client.post("/event-callbacks", json=_tmpl_payload(conversation_template.id))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["conversation_template_id"] == str(conversation_template.id)
        assert body["conversation_id"] is None

    async def test_create_rejects_both_links(
        self,
        client: AsyncClient,
        conversation: Conversation,
        conversation_template: ConversationTemplate,
    ) -> None:
        payload = _conv_payload(conversation.id)
        payload["conversation_template_id"] = str(conversation_template.id)
        resp = await client.post("/event-callbacks", json=payload)
        assert resp.status_code == 422

    async def test_create_rejects_neither_link(self, client: AsyncClient) -> None:
        payload = {
            "event_kind": "MessageEvent",
            "processor": _processor_json(),
        }
        resp = await client.post("/event-callbacks", json=payload)
        assert resp.status_code == 422

    async def test_search_lists_callbacks(
        self, client: AsyncClient, conversation: Conversation
    ) -> None:
        for i in range(3):
            resp = await client.post(
                "/event-callbacks", json=_conv_payload(conversation.id, event_kind=f"kind_{i}")
            )
            assert resp.status_code == 201
        resp = await client.get("/event-callbacks")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 3

    async def test_count(self, client: AsyncClient, conversation: Conversation) -> None:
        resp = await client.get("/event-callbacks/count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0
        await client.post("/event-callbacks", json=_conv_payload(conversation.id))
        resp = await client.get("/event-callbacks/count")
        assert resp.json()["count"] == 1

    async def test_update_changes_fields(
        self, client: AsyncClient, conversation: Conversation
    ) -> None:
        resp = await client.post("/event-callbacks", json=_conv_payload(conversation.id))
        cb_id = resp.json()["id"]
        resp = await client.patch(
            f"/event-callbacks/{cb_id}",
            json={"event_kind": "Updated", "status": "SUCCESS", "detail": "ok"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["event_kind"] == "Updated"
        assert body["status"] == "SUCCESS"
        assert body["detail"] == "ok"

    async def test_delete_removes(self, client: AsyncClient, conversation: Conversation) -> None:
        resp = await client.post("/event-callbacks", json=_conv_payload(conversation.id))
        cb_id = resp.json()["id"]
        resp = await client.delete(f"/event-callbacks/{cb_id}")
        assert resp.status_code == 204
        resp = await client.get(f"/event-callbacks/{cb_id}")
        assert resp.status_code == 404

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/event-callbacks/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_read(self, client: AsyncClient, conversation: Conversation) -> None:
        ids = []
        for i in range(3):
            resp = await client.post(
                "/event-callbacks", json=_conv_payload(conversation.id, event_kind=f"k{i}")
            )
            ids.append(resp.json()["id"])
        missing = str(uuid.uuid4())
        resp = await client.get(
            "/event-callbacks/batch",
            params=[("ids", ids[1]), ("ids", missing), ("ids", ids[0])],
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0] is not None and items[0]["id"] == ids[1]
        assert items[1] is None
        assert items[2] is not None and items[2]["id"] == ids[0]

    async def test_batch_write_mixed_cud(
        self, client: AsyncClient, conversation: Conversation
    ) -> None:
        resp = await client.post(
            "/event-callbacks", json=_conv_payload(conversation.id, event_kind="orig")
        )
        cb_id = resp.json()["id"]
        batch_payload = {
            "operations": [
                {
                    "op": "create",
                    "data": _conv_payload(conversation.id, event_kind="new"),
                },
                {
                    "op": "update",
                    "id": cb_id,
                    "data": {"event_kind": "updated", "status": "SUCCESS"},
                },
            ]
        }
        resp = await client.post("/event-callbacks/batch", json=batch_payload)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0] is not None and items[0]["event_kind"] == "new"
        assert items[1] is not None and items[1]["event_kind"] == "updated"

    async def test_batch_write_delete_in_batch(
        self, client: AsyncClient, conversation: Conversation
    ) -> None:
        resp = await client.post("/event-callbacks", json=_conv_payload(conversation.id))
        cb_id = resp.json()["id"]
        resp = await client.post(
            "/event-callbacks/batch",
            json={"operations": [{"op": "delete", "id": cb_id}]},
        )
        assert resp.status_code == 200, resp.text
        resp = await client.get(f"/event-callbacks/{cb_id}")
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Role schema parity
# --------------------------------------------------------------------------- #


class TestEventCallbackRolePermission:
    async def test_role_create_accepts_event_callback_permission(self) -> None:
        from openhands.ev2.role.role_schemas import RoleCreate

        payload = RoleCreate(
            name="cb-admin",
            event_callback_permission=Permitted(),
        )
        assert payload.event_callback_permission is not None

    async def test_role_create_accepts_creator_permission(self) -> None:
        from openhands.ev2.role.role_schemas import RoleCreate

        payload = RoleCreate(
            name="cb-creator",
            event_callback_permission=CreatorPermission(),
        )
        assert payload.event_callback_permission is not None
