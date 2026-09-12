"""Route tests for the conversation feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import (
    assign_role as _assign_role,
)
from tests.unit._auth_helpers import (
    make_principal as _make_principal,
)
from tests.unit._auth_helpers import (
    make_sandbox_config as _make_sandbox_config,
)

from openhands.ev2.conversation.conversation_security import ConversationAccess
from openhands.ev2.security.security_models import Permitted
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


def _payload(sandbox_config_id: uuid.UUID, **overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "title": "route test conversation",
        "sandbox_config_id": str(sandbox_config_id),
        "llm_model": "claude-sonnet-4",
        "agent_kind": "openhands",
        "selected_repository": "org/repo",
        "selected_branch": "main",
        "trigger": "manual",
    }
    data.update(overrides)
    return data


async def _create(
    client: AsyncClient, sandbox_config_id: uuid.UUID, **overrides: object
) -> dict[str, object]:
    resp = await client.post("/conversations", json=_payload(sandbox_config_id, **overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestCreateConversationRoute:
    async def test_create_conversation(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        body = await _create(client, config.id)
        assert body["title"] == "route test conversation"
        assert body["sandbox_config_id"] == str(config.id)
        assert body["accumulated_cost"] == 0.0
        assert body["prompt_tokens"] == 0
        assert body["completion_tokens"] == 0
        assert body["total_tokens"] == 0
        assert uuid.UUID(body["id"])

    async def test_create_conversation_minimal(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await client.post(
            "/conversations",
            json={
                "title": "minimal",
                "sandbox_config_id": str(config.id),
                "llm_model": "claude-sonnet-4",
                "agent_kind": "openhands",
                "trigger": "webhook",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["selected_repository"] is None
        assert body["selected_branch"] is None

    async def test_create_conversation_blank_title_returns_422(
        self, client: AsyncClient, session
    ) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        resp = await client.post("/conversations", json=_payload(config.id, title="  "))
        assert resp.status_code == 422


class TestGetConversationRoute:
    async def test_get_existing(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        created = await _create(client, config.id)
        resp = await client.get(f"/conversations/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "route test conversation"

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/conversations/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/conversations/not-a-uuid")
        assert resp.status_code == 422


class TestSearchConversationsRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/conversations")
        assert resp.status_code == 200
        assert resp.json() == {"items": [], "next_cursor": None, "limit": 50}

    async def test_search_and_filter(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        await _create(client, config.id, title="alpha", trigger="manual")
        beta = await _create(client, config.id, title="beta", trigger="webhook")

        resp = await client.get("/conversations", params={"title__contains": "BET"})
        assert resp.status_code == 200
        assert [i["id"] for i in resp.json()["items"]] == [beta["id"]]

        resp = await client.get("/conversations", params={"trigger__eq": "manual"})
        assert len(resp.json()["items"]) == 1

        resp = await client.get("/conversations", params={"sandbox_config_id__eq": str(config.id)})
        assert len(resp.json()["items"]) == 2

    async def test_search_pagination(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        for i in range(3):
            await _create(client, config.id, title=f"c{i}")

        page1 = (await client.get("/conversations", params={"limit": 2})).json()
        assert len(page1["items"]) == 2
        assert page1["next_cursor"] is not None
        page2 = (
            await client.get("/conversations", params={"limit": 2, "cursor": page1["next_cursor"]})
        ).json()
        assert len(page2["items"]) == 1
        assert page2["next_cursor"] is None

    async def test_count(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        assert (await client.get("/conversations/count")).json() == {"count": 0}
        await _create(client, config.id, title="counted")
        assert (await client.get("/conversations/count")).json() == {"count": 1}
        resp = await client.get("/conversations/count", params={"title__contains": "zzz"})
        assert resp.json() == {"count": 0}


class TestUpdateConversationRoute:
    async def test_patch_metrics(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        created = await _create(client, config.id)
        resp = await client.patch(
            f"/conversations/{created['id']}",
            json={
                "accumulated_cost": 2.5,
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["accumulated_cost"] == 2.5
        assert body["prompt_tokens"] == 10
        assert body["completion_tokens"] == 5
        assert body["total_tokens"] == 15
        assert body["title"] == "route test conversation"

    async def test_patch_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/conversations/{uuid.uuid4()}", json={"title": "x"})
        assert resp.status_code == 404

    async def test_patch_negative_tokens_returns_422(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        created = await _create(client, config.id)
        resp = await client.patch(f"/conversations/{created['id']}", json={"prompt_tokens": -1})
        assert resp.status_code == 422


class TestDeleteConversationRoute:
    async def test_delete(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        created = await _create(client, config.id)
        resp = await client.delete(f"/conversations/{created['id']}")
        assert resp.status_code == 204
        assert (await client.get(f"/conversations/{created['id']}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.delete(f"/conversations/{uuid.uuid4()}")).status_code == 404


class TestBatchReadRoute:
    async def test_batch_read_aligned(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        first = await _create(client, config.id, title="first")
        second = await _create(client, config.id, title="second")
        missing = uuid.uuid4()
        resp = await client.get(
            "/conversations/batch",
            params=[("ids", second["id"]), ("ids", str(missing)), ("ids", first["id"])],
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert [i["id"] if i else None for i in items] == [second["id"], None, first["id"]]

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/conversations/batch")
        assert resp.status_code == 200
        assert resp.json() == {"items": []}

    async def test_batch_read_over_limit_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/conversations/batch", params=[("ids", str(uuid.uuid4()))] * 101)
        assert resp.status_code == 422


class TestBatchWriteRoute:
    async def test_batch_write_mixed(self, client: AsyncClient, session) -> None:
        config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        existing = await _create(client, config.id, title="existing")
        doomed = await _create(client, config.id, title="doomed")
        resp = await client.post(
            "/conversations/batch",
            json={
                "operations": [
                    {"op": "create", "data": _payload(config.id, title="new")},
                    {"op": "update", "id": existing["id"], "data": {"title": "renamed"}},
                    {"op": "delete", "id": doomed["id"]},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["title"] == "new"
        assert items[1]["title"] == "renamed"
        assert items[2] is None
        assert (await client.get(f"/conversations/{doomed['id']}")).status_code == 404

    async def test_batch_write_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/conversations/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(uuid.uuid4()), "data": {"title": "x"}},
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_write_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/conversations/batch",
            json={"operations": [{"op": "delete", "id": str(uuid.uuid4())}]},
        )
        assert resp.status_code == 404


class TestConversationAccessPolicy:
    """Non-admin users with ConversationAccess get scoped read/search only."""

    async def _seed_conversations(self, client: AsyncClient, session):
        """One config+conversation for the restricted user, one for the admin."""
        restricted = await _make_principal(
            session, email="restricted@example.com", username="restricted"
        )
        own_config = await _make_sandbox_config(session, creator_id=restricted.id)
        admin_config = await _make_sandbox_config(session, creator_id=_TEST_USER_ID)
        await session.commit()
        own = await _create(client, own_config.id, title="own")
        foreign = await _create(client, admin_config.id, title="foreign")
        return own_config, own, foreign, restricted

    async def test_scoped_read_and_search(self, client: AsyncClient, session) -> None:
        _own_config, own, foreign, restricted = await self._seed_conversations(client, session)
        await _assign_role(
            session,
            restricted.id,
            {"conversation_permission": ConversationAccess()},
            role_name="restricted-conv",
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get("/conversations", headers=headers)
        assert resp.status_code == 200
        assert [i["id"] for i in resp.json()["items"]] == [own["id"]]

        resp = await client.get(f"/conversations/{own['id']}", headers=headers)
        assert resp.status_code == 200
        # A conversation on someone else's sandbox config is invisible (404,
        # never 403 — existence is not leaked).
        resp = await client.get(f"/conversations/{foreign['id']}", headers=headers)
        assert resp.status_code == 404

        resp = await client.get(
            "/conversations/batch",
            params=[("ids", own["id"]), ("ids", foreign["id"])],
            headers=headers,
        )
        assert [i["id"] if i else None for i in resp.json()["items"]] == [own["id"], None]

        resp = await client.get("/conversations/count", headers=headers)
        assert resp.json() == {"count": 1}

    async def test_writes_denied(self, client: AsyncClient, session) -> None:
        own_config, own, _foreign, restricted = await self._seed_conversations(client, session)
        await _assign_role(
            session,
            restricted.id,
            {"conversation_permission": ConversationAccess()},
            role_name="restricted-conv",
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}

        assert (
            await client.post("/conversations", json=_payload(own_config.id), headers=headers)
        ).status_code == 403
        assert (
            await client.patch(f"/conversations/{own['id']}", json={"title": "x"}, headers=headers)
        ).status_code == 403
        assert (
            await client.delete(f"/conversations/{own['id']}", headers=headers)
        ).status_code == 403
        resp = await client.post(
            "/conversations/batch",
            json={"operations": [{"op": "delete", "id": own["id"]}]},
            headers=headers,
        )
        assert resp.status_code == 403

    async def test_permitted_role_gets_full_access(self, client: AsyncClient, session) -> None:
        _own_config, own, foreign, restricted = await self._seed_conversations(client, session)
        await _assign_role(
            session,
            restricted.id,
            {"conversation_permission": Permitted()},
            role_name="restricted-admin",
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get("/conversations", headers=headers)
        assert {i["id"] for i in resp.json()["items"]} == {own["id"], foreign["id"]}
        assert (
            await client.patch(f"/conversations/{own['id']}", json={"title": "x"}, headers=headers)
        ).status_code == 200

    async def test_no_role_denied(self, client: AsyncClient, session) -> None:
        principal = await _make_principal(session, email="norole@example.com", username="norole")
        await session.commit()
        headers = {"Authorization": f"Bearer {create_auth_token(principal.id)}"}
        assert (await client.get("/conversations", headers=headers)).status_code == 403

    async def test_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport
        from httpx import AsyncClient as RawClient

        transport = ASGITransport(app=app)
        async with RawClient(transport=transport, base_url="http://test") as ac:
            assert (await ac.get("/conversations")).status_code == 403

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        assert (await client.get("/conversations?cursor=not-a-uuid")).status_code == 400
