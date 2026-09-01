"""Route tests for MCP server config endpoints."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted
from openhands.ev2.util.auth_token import create_auth_token


def _stdio_payload(display_name: str = "filesystem") -> dict[str, object]:
    return {
        "display_name": display_name,
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        "env": {"TOKEN": "env-secret"},
        "headers": {"X-Token": "header-secret"},
        "auth": {"strategy": "bearer", "value": "bearer-secret"},
    }


async def _create_config(client: AsyncClient) -> dict[str, object]:
    response = await client.post("/mcp-server-configs", json=_stdio_payload())
    assert response.status_code == 201, response.text
    return response.json()


async def _test_admin_role_id(client: AsyncClient) -> str:
    response = await client.get("/roles", params={"name__eq": "test-admin"})
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert len(items) == 1
    return str(items[0]["id"])


class TestMCPServerConfigRoutes:
    async def test_crud_and_batch(self, client: AsyncClient) -> None:
        created = await _create_config(client)
        config_id = str(created["id"])

        assert created["env"] == {"TOKEN": "**********"}
        assert created["headers"] == {"X-Token": "**********"}
        assert created["auth"] == {"strategy": "bearer", "value": "**********"}

        get_response = await client.get(f"/mcp-server-configs/{config_id}")
        assert get_response.status_code == 200, get_response.text
        assert get_response.json()["id"] == config_id

        batch_response = await client.get("/mcp-server-configs/batch", params={"ids": config_id})
        assert batch_response.status_code == 200, batch_response.text
        assert batch_response.json()["items"][0]["id"] == config_id

        patch_response = await client.patch(
            f"/mcp-server-configs/{config_id}",
            json={"display_name": "renamed", "enabled": False},
        )
        assert patch_response.status_code == 200, patch_response.text
        patched = patch_response.json()
        assert patched["display_name"] == "renamed"
        assert patched["enabled"] is False

        count_response = await client.get("/mcp-server-configs/count")
        assert count_response.status_code == 200, count_response.text
        assert count_response.json()["count"] >= 1

        delete_response = await client.delete(f"/mcp-server-configs/{config_id}")
        assert delete_response.status_code == 204, delete_response.text

    async def test_search_and_batch_limits(self, client: AsyncClient) -> None:
        display_name = f"search-{uuid.uuid4()}"
        create_response = await client.post(
            "/mcp-server-configs", json=_stdio_payload(display_name)
        )
        assert create_response.status_code == 201, create_response.text
        created = create_response.json()

        search_response = await client.get(
            "/mcp-server-configs",
            params={"limit": 1, "display_name__contains": display_name},
        )
        assert search_response.status_code == 200, search_response.text
        assert search_response.json()["items"][0]["id"] == created["id"]

        invalid_cursor = await client.get("/mcp-server-configs", params={"cursor": "bad"})
        assert invalid_cursor.status_code == 400

        too_many_ids = await client.get(
            "/mcp-server-configs/batch",
            params=[("ids", str(uuid.uuid4())) for _ in range(101)],
        )
        assert too_many_ids.status_code == 422

    async def test_batch_write_update_delete_and_not_found(self, client: AsyncClient) -> None:
        response = await client.post(
            "/mcp-server-configs/batch",
            json={"operations": [{"op": "create", "data": _stdio_payload("batch")}]},
        )
        assert response.status_code == 200, response.text
        item = response.json()["items"][0]
        config_id = item["id"]
        assert item["display_name"] == "batch"

        update_delete = await client.post(
            "/mcp-server-configs/batch",
            json={
                "operations": [
                    {"op": "update", "id": config_id, "data": {"display_name": "batched"}},
                    {"op": "delete", "id": config_id},
                ]
            },
        )
        assert update_delete.status_code == 200, update_delete.text
        items = update_delete.json()["items"]
        assert items[0]["display_name"] == "batched"
        assert items[1] is None

        missing = str(uuid.uuid4())
        missing_update = await client.post(
            "/mcp-server-configs/batch",
            json={"operations": [{"op": "update", "id": missing, "data": {"enabled": False}}]},
        )
        assert missing_update.status_code == 404

    async def test_missing_config_returns_404(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        assert (await client.get(f"/mcp-server-configs/{missing}")).status_code == 404
        assert (
            await client.patch(f"/mcp-server-configs/{missing}", json={"display_name": "missing"})
        ).status_code == 404
        assert (await client.delete(f"/mcp-server-configs/{missing}")).status_code == 404

    async def test_invalid_config_returns_422(self, client: AsyncClient) -> None:
        response = await client.post(
            "/mcp-server-configs",
            json={"display_name": "bad", "transport": "stdio"},
        )
        assert response.status_code == 422


class TestRoleMCPServerConfigPermissionRoutes:
    async def test_crud_and_batch(self, client: AsyncClient) -> None:
        config = await _create_config(client)
        role_id = await _test_admin_role_id(client)
        payload = {
            "role_id": role_id,
            "mcp_server_config_id": str(config["id"]),
            "read_enabled": True,
        }

        create_response = await client.post("/role-mcp-server-config-permissions", json=payload)
        assert create_response.status_code == 201, create_response.text
        grant = create_response.json()
        grant_id = grant["id"]
        assert grant["read_enabled"] is True
        assert grant["update_enabled"] is False

        get_response = await client.get(f"/role-mcp-server-config-permissions/{grant_id}")
        assert get_response.status_code == 200, get_response.text
        assert get_response.json()["id"] == grant_id

        batch_response = await client.get(
            "/role-mcp-server-config-permissions/batch",
            params={"ids": grant_id},
        )
        assert batch_response.status_code == 200, batch_response.text
        assert batch_response.json()["items"][0]["id"] == grant_id

        patch_response = await client.patch(
            f"/role-mcp-server-config-permissions/{grant_id}",
            json={"update_enabled": True},
        )
        assert patch_response.status_code == 200, patch_response.text
        assert patch_response.json()["update_enabled"] is True

        count_response = await client.get("/role-mcp-server-config-permissions/count")
        assert count_response.status_code == 200, count_response.text
        assert count_response.json()["count"] >= 1

        delete_response = await client.delete(f"/role-mcp-server-config-permissions/{grant_id}")
        assert delete_response.status_code == 204, delete_response.text

    async def test_batch_write_update_and_delete(self, client: AsyncClient) -> None:
        config = await _create_config(client)
        role_id = await _test_admin_role_id(client)
        response = await client.post(
            "/role-mcp-server-config-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "role_id": role_id,
                            "mcp_server_config_id": str(config["id"]),
                            "read_enabled": True,
                            "delete_enabled": True,
                        },
                    }
                ]
            },
        )
        assert response.status_code == 200, response.text
        item = response.json()["items"][0]
        grant_id = item["id"]
        assert item["delete_enabled"] is True

        update_delete = await client.post(
            "/role-mcp-server-config-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": grant_id, "data": {"update_enabled": True}},
                    {"op": "delete", "id": grant_id},
                ]
            },
        )
        assert update_delete.status_code == 200, update_delete.text
        items = update_delete.json()["items"]
        assert items[0]["update_enabled"] is True
        assert items[1] is None

        missing = str(uuid.uuid4())
        missing_update = await client.post(
            "/role-mcp-server-config-permissions/batch",
            json={"operations": [{"op": "update", "id": missing, "data": {"read_enabled": True}}]},
        )
        assert missing_update.status_code == 404

    async def test_search_limits_conflict_orphan_and_missing(self, client: AsyncClient) -> None:
        config = await _create_config(client)
        role_id = await _test_admin_role_id(client)
        payload = {
            "role_id": role_id,
            "mcp_server_config_id": str(config["id"]),
            "read_enabled": True,
            "update_enabled": True,
            "delete_enabled": True,
        }
        create_response = await client.post("/role-mcp-server-config-permissions", json=payload)
        assert create_response.status_code == 201, create_response.text
        grant_id = create_response.json()["id"]

        search_response = await client.get(
            "/role-mcp-server-config-permissions",
            params={"limit": 1, "role_id__eq": role_id},
        )
        assert search_response.status_code == 200, search_response.text
        assert search_response.json()["items"][0]["id"] == grant_id

        invalid_cursor = await client.get(
            "/role-mcp-server-config-permissions",
            params={"cursor": "bad"},
        )
        assert invalid_cursor.status_code == 400

        duplicate = await client.post("/role-mcp-server-config-permissions", json=payload)
        assert duplicate.status_code == 409

        orphan = await client.post(
            "/role-mcp-server-config-permissions",
            json={**payload, "mcp_server_config_id": str(uuid.uuid4())},
        )
        assert orphan.status_code == 404

        too_many_ids = await client.get(
            "/role-mcp-server-config-permissions/batch",
            params=[("ids", str(uuid.uuid4())) for _ in range(101)],
        )
        assert too_many_ids.status_code == 422

        missing = str(uuid.uuid4())
        assert (
            await client.get(f"/role-mcp-server-config-permissions/{missing}")
        ).status_code == 404
        assert (
            await client.patch(
                f"/role-mcp-server-config-permissions/{missing}",
                json={"read_enabled": True},
            )
        ).status_code == 404
        assert (
            await client.delete(f"/role-mcp-server-config-permissions/{missing}")
        ).status_code == 404


class TestRoleMCPServerConfigGrantAuthorization:
    """Regression tests: MCP-config-grant management is governed by
    ``mcp_server_config_grant_permission``, not by ``role_permission``.

    A principal who may only edit role metadata must not be able to grant a
    role access to MCP server configs (privilege escalation / credential
    exfiltration).
    """

    async def test_role_admin_cannot_manage_grants(self, client: AsyncClient, session) -> None:
        """role_permission=Permitted alone (no grant permission) => 403."""
        principal = await _make_principal(session, email="mg@example.com", username="mg")
        await _assign_role(session, principal.id, {"role_permission": Permitted()})
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        assert (
            await client.get("/role-mcp-server-config-permissions", headers=headers)
        ).status_code == 403
        assert (
            await client.post(
                "/role-mcp-server-config-permissions",
                json={"role_id": str(uuid.uuid4()), "mcp_server_config_id": str(uuid.uuid4())},
                headers=headers,
            )
        ).status_code == 403
        assert (
            await client.post(
                "/role-mcp-server-config-permissions/batch",
                json={
                    "operations": [
                        {
                            "op": "create",
                            "data": {
                                "role_id": str(uuid.uuid4()),
                                "mcp_server_config_id": str(uuid.uuid4()),
                            },
                        }
                    ]
                },
                headers=headers,
            )
        ).status_code == 403

    async def test_grant_manager_can_manage_grants(self, client: AsyncClient, session) -> None:
        """mcp_server_config_grant_permission=Permitted manages grants (but
        cannot read roles)."""
        principal = await _make_principal(session, email="mgr@example.com", username="mgr")
        await _assign_role(
            session, principal.id, {"mcp_server_config_grant_permission": Permitted()}
        )
        await session.commit()
        token = create_auth_token(principal.id)
        headers = {"Authorization": f"Bearer {token}"}

        assert (
            await client.get("/role-mcp-server-config-permissions", headers=headers)
        ).status_code == 200
        # Passes authz, fails on orphan FK.
        assert (
            await client.post(
                "/role-mcp-server-config-permissions",
                json={"role_id": str(uuid.uuid4()), "mcp_server_config_id": str(uuid.uuid4())},
                headers=headers,
            )
        ).status_code == 404
        # Role administration is not conferred.
        assert (await client.get("/roles", headers=headers)).status_code == 403
