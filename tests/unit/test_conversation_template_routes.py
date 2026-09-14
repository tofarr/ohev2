"""Route tests for the ``/conversation-templates`` governed resource."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import CreatorPermission, Denied, Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


def _payload(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "default template",
        "agent_kind": "openhands",
        "llm_id": None,
        "mcp_server_config_ids": [],
        "secret_provider_ids": [],
        "static_secret_ids": [],
        "agent_config": {"agent": "CodeActAgent"},
        "conversation_config": {"max_iterations": 100},
        "system_message_suffix": "suffix",
        "default_callbacks": [],
    }
    data.update(overrides)
    return data


async def _create_template(client: AsyncClient, **overrides: object) -> dict[str, object]:
    response = await client.post("/conversation-templates", json=_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


class TestConversationTemplateRoutes:
    async def test_full_crud(self, client: AsyncClient) -> None:
        created = await _create_template(client, name="crud-tpl")
        template_id = created["id"]
        assert created["name"] == "crud-tpl"
        assert created["agent_kind"] == "openhands"
        assert created["creator_id"] == str(_TEST_USER_ID)
        assert created["agent_config"] == {"agent": "CodeActAgent"}
        assert created["conversation_config"] == {"max_iterations": 100}

        get_response = await client.get(f"/conversation-templates/{template_id}")
        assert get_response.status_code == 200, get_response.text
        assert get_response.json()["id"] == template_id

        batch_response = await client.get(
            "/conversation-templates/batch", params={"ids": template_id}
        )
        assert batch_response.status_code == 200, batch_response.text
        items = batch_response.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == template_id

        patch_response = await client.patch(
            f"/conversation-templates/{template_id}",
            json={"name": "renamed"},
        )
        assert patch_response.status_code == 200, patch_response.text
        assert patch_response.json()["name"] == "renamed"
        # Unset fields unchanged.
        assert patch_response.json()["system_message_suffix"] == "suffix"

        # Explicitly clear a nullable field.
        cleared = await client.patch(
            f"/conversation-templates/{template_id}",
            json={"system_message_suffix": None},
        )
        assert cleared.status_code == 200
        assert cleared.json()["system_message_suffix"] is None

        delete_response = await client.delete(f"/conversation-templates/{template_id}")
        assert delete_response.status_code == 204, delete_response.text
        assert (await client.get(f"/conversation-templates/{template_id}")).status_code == 404

    async def test_search_filter_count_and_pagination(self, client: AsyncClient) -> None:
        tag = str(uuid.uuid4())
        created = await _create_template(client, name=f"search-{tag}")
        template_id = created["id"]

        search_response = await client.get(
            "/conversation-templates", params={"limit": 5, "name__contains": tag}
        )
        assert search_response.status_code == 200, search_response.text
        assert any(i["id"] == template_id for i in search_response.json()["items"])

        count_response = await client.get("/conversation-templates/count")
        assert count_response.status_code == 200, count_response.text
        assert count_response.json()["count"] >= 1

        invalid_cursor = await client.get("/conversation-templates", params={"cursor": "zzz"})
        assert invalid_cursor.status_code == 400

        # agent_kind is a declared filter.
        kind_response = await client.get(
            "/conversation-templates", params={"agent_kind__eq": "acp"}
        )
        assert kind_response.status_code == 200, kind_response.text
        assert kind_response.json()["items"] == []

    async def test_invalid_agent_kind_returns_422(self, client: AsyncClient) -> None:
        response = await client.post("/conversation-templates", json=_payload(agent_kind="llm"))
        assert response.status_code == 422

    async def test_blank_name_returns_422(self, client: AsyncClient) -> None:
        response = await client.post("/conversation-templates", json=_payload(name="  "))
        assert response.status_code == 422

    async def test_missing_returns_404(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        assert (await client.get(f"/conversation-templates/{missing}")).status_code == 404
        assert (
            await client.patch(f"/conversation-templates/{missing}", json={"name": "x"})
        ).status_code == 404
        assert (await client.delete(f"/conversation-templates/{missing}")).status_code == 404

    async def test_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        assert (await client.get("/conversation-templates/not-a-uuid")).status_code == 422

    async def test_referenced_llm_missing_returns_404(self, client: AsyncClient) -> None:
        missing_llm = str(uuid.uuid4())
        response = await client.post("/conversation-templates", json=_payload(llm_id=missing_llm))
        assert response.status_code == 404
        assert "Referenced entity not found" in response.text

    async def test_update_lists_replace_wholesale(self, client: AsyncClient) -> None:
        created = await _create_template(client)
        mcp_id = str(uuid.uuid4())
        replaced = await client.patch(
            f"/conversation-templates/{created['id']}",
            json={"mcp_server_config_ids": [mcp_id]},
        )
        assert replaced.status_code == 200
        assert replaced.json()["mcp_server_config_ids"] == [mcp_id]

    async def test_batch_write(self, client: AsyncClient) -> None:
        created = await _create_template(client, name="batch-create")
        template_id = created["id"]

        update_delete = await client.post(
            "/conversation-templates/batch",
            json={
                "operations": [
                    {"op": "update", "id": template_id, "data": {"name": "batch-renamed"}},
                    {"op": "delete", "id": template_id},
                ]
            },
        )
        assert update_delete.status_code == 200, update_delete.text
        items = update_delete.json()["items"]
        assert items[0]["name"] == "batch-renamed"
        assert items[1] is None

        # Batch create.
        create_response = await client.post(
            "/conversation-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _payload(name="batch-new")},
                ]
            },
        )
        assert create_response.status_code == 200, create_response.text
        assert create_response.json()["items"][0]["name"] == "batch-new"

    async def test_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport
        from httpx import AsyncClient as RawClient

        transport = ASGITransport(app=app)
        async with RawClient(transport=transport, base_url="http://test") as ac:
            # The single-item create is denied by the permission dependency (403);
            # the batch endpoint resolves per-action filters without raising, so
            # the route's auth check fires first (401).
            assert (
                await ac.post(
                    "/conversation-templates",
                    json=_payload(name="anon"),
                )
            ).status_code == 403
            assert (
                await ac.post(
                    "/conversation-templates/batch",
                    json={"operations": [{"op": "create", "data": _payload(name="anon")}]},
                )
            ).status_code == 401

    async def test_batch_read_rejects_too_many_ids(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        response = await client.get(
            "/conversation-templates/batch",
            params=[("ids", i) for i in ids],
        )
        assert response.status_code == 422

    async def test_batch_update_missing_returns_404(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        response = await client.post(
            "/conversation-templates/batch",
            json={
                "operations": [
                    {"op": "update", "id": missing, "data": {"name": "nope"}},
                ]
            },
        )
        assert response.status_code == 404
        assert "Conversation template not found" in response.text

    async def test_batch_create_missing_llm_returns_404(self, client: AsyncClient) -> None:
        response = await client.post(
            "/conversation-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _payload(name="bad-llm", llm_id=str(uuid.uuid4()))},
                ]
            },
        )
        assert response.status_code == 404
        assert "Referenced entity not found" in response.text

    async def test_update_with_missing_llm_returns_404(self, client: AsyncClient) -> None:
        created = await _create_template(client, name="update-llm")
        response = await client.patch(
            f"/conversation-templates/{created['id']}",
            json={"llm_id": str(uuid.uuid4())},
        )
        assert response.status_code == 404
        assert "Referenced entity not found" in response.text

    async def test_batch_denies_when_action_not_granted(self, client: AsyncClient, session) -> None:
        restricted = await _make_principal(
            session, email="tpl-restricted@example.com", username="tpl-restricted"
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}

        # Only READ/search granted via ReadOnly; create+delete are denied.
        await _assign_role(
            session,
            restricted.id,
            {"conversation_template_permission": ReadOnly()},
        )
        await session.commit()

        response = await client.post(
            "/conversation-templates/batch",
            headers=headers,
            json={
                "operations": [
                    {"op": "create", "data": _payload(name="nope")},
                ]
            },
        )
        assert response.status_code == 403, response.text

    async def test_batch_create_out_of_scope_returns_403(
        self, client: AsyncClient, session
    ) -> None:
        """A non-None create filter that rejects the payload yields a scope 403.

        ``CreatorPermission(on_create=Denied())`` reduces to a non-None
        ``NoneSearchFilter``, so the batch path reports a create-scope error
        rather than a generic missing-grant error.
        """
        restricted = await _make_principal(
            session, email="tpl-scope2@example.com", username="tpl-scope2"
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}
        await _assign_role(
            session,
            restricted.id,
            {
                "conversation_template_permission": CreatorPermission(
                    on_match=Permitted(),
                    on_create=Denied(),
                )
            },
        )
        await session.commit()

        response = await client.post(
            "/conversation-templates/batch",
            headers=headers,
            json={
                "operations": [
                    {"op": "create", "data": _payload(name="out-of-scope")},
                ]
            },
        )
        assert response.status_code == 403, response.text


class TestConversationTemplateAuthorization:
    async def test_denied_without_role(self, client: AsyncClient, session) -> None:
        restricted = await _make_principal(
            session, email="tpl-denied@example.com", username="tpl-denied"
        )
        await session.commit()
        token = create_auth_token(restricted.id)
        headers = {"Authorization": f"Bearer {token}"}

        # No role → no conversation_template_permission → deny every action.
        response = await client.get("/conversation-templates", headers=headers)
        assert response.status_code == 403, response.text
        response = await client.post(
            "/conversation-templates",
            headers=headers,
            json=_payload(name="nope"),
        )
        assert response.status_code == 403, response.text

    async def test_creator_manages_own_and_reads_only_granted(
        self, client: AsyncClient, session
    ) -> None:
        """CreatorPermission for a limited user: on_match grants creator access.

        The seeded test-admin principal is unaffected; we drop the admin role
        for a separate user and verify its CreatorPermission scopes.
        """
        principal = await _make_principal(
            session, email="tpl-creator@example.com", username="tpl-creator"
        )
        await session.commit()
        await _assign_role(
            session,
            principal.id,
            {
                "conversation_template_permission": CreatorPermission(
                    on_match=Permitted(),
                    on_create=Permitted(),
                )
            },
        )
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        created = await client.post(
            "/conversation-templates",
            headers=headers,
            json=_payload(name="own-tpl"),
        )
        assert created.status_code == 201, created.text
        own_id = created.json()["id"]

        # Can read its own template and manage it.
        get_response = await client.get(f"/conversation-templates/{own_id}", headers=headers)
        assert get_response.status_code == 200
        patch_response = await client.patch(
            f"/conversation-templates/{own_id}",
            headers=headers,
            json={"name": "renamed-own"},
        )
        assert patch_response.status_code == 200

        # Can't see a template created by another user (out of scope → 404).
        other = await _create_template(client, name="other-user-tpl")
        hidden = await client.get(f"/conversation-templates/{other['id']}", headers=headers)
        assert hidden.status_code == 404

        delete_response = await client.delete(f"/conversation-templates/{own_id}", headers=headers)
        assert delete_response.status_code == 204

    async def test_creator_scope_applies_to_reads_not_create(
        self, client: AsyncClient, session
    ) -> None:
        """``on_create`` gates CREATE directly; the scope match applies to non-CREATE.

        A ``CreatorPermission`` with an ``on_match=ReadOnly()`` (so the
        principal can read/search but not update/delete their own rows) still
        permits CREATing a new row.
        """
        principal = await _make_principal(
            session, email="tpl-scope@example.com", username="tpl-scope"
        )
        await session.commit()
        await _assign_role(
            session,
            principal.id,
            {
                "conversation_template_permission": CreatorPermission(
                    on_match=ReadOnly(),
                    on_create=Permitted(),
                )
            },
        )
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}
        created = await client.post(
            "/conversation-templates", headers=headers, json=_payload(name="own-create")
        )
        assert created.status_code == 201, created.text

        # UPDATE falls back to on_match (ReadOnly) → out-of-scope rows 404
        # fail-closed (existence is not leaked).
        update_response = await client.patch(
            f"/conversation-templates/{created.json()['id']}",
            headers=headers,
            json={"name": "nope"},
        )
        assert update_response.status_code == 404, update_response.text
