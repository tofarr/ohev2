"""Route tests for MCP server config endpoints."""

from __future__ import annotations

from httpx import AsyncClient


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

    async def test_batch_write(self, client: AsyncClient) -> None:
        response = await client.post(
            "/mcp-server-configs/batch",
            json={"operations": [{"op": "create", "data": _stdio_payload("batch")}]},
        )
        assert response.status_code == 200, response.text
        item = response.json()["items"][0]
        assert item["display_name"] == "batch"

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

    async def test_batch_write(self, client: AsyncClient) -> None:
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
        assert item["delete_enabled"] is True
