"""Route tests for MCP server config endpoints."""

from __future__ import annotations

import uuid

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


class TestMCPServerConfigRouteErrorPaths:
    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        assert (await client.get("/mcp-server-configs?cursor=not-a-uuid")).status_code == 400

    async def test_batch_write_delete_missing_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/mcp-server-configs/batch",
            json={"operations": [{"op": "delete", "id": str(uuid.uuid4())}]},
        )
        assert resp.status_code == 404

    async def test_batch_write_update_missing_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/mcp-server-configs/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(uuid.uuid4()), "data": {"name": "x"}},
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_empty_ops_rejected(self, client: AsyncClient) -> None:
        assert (
            await client.post("/mcp-server-configs/batch", json={"operations": []})
        ).status_code == 422

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/mcp-server-configs/{uuid.uuid4()}",
            json={"name": "x"},
        )
        assert resp.status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.delete(f"/mcp-server-configs/{uuid.uuid4()}")).status_code == 404
