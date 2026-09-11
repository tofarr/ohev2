"""Route tests for the DB-backed ``/sandbox/sandbox-configs`` REST surface."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient


async def _create_template(client: AsyncClient) -> str:
    resp = await client.post(
        "/sandbox/sandbox-templates",
        json={"docker_image_tag": f"img-{uuid.uuid4()}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


class TestSandboxConfigRoutes:
    async def test_crud_lifecycle(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)

        created = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id, "enabled": True},
        )
        assert created.status_code == 201, created.text
        config = created.json()
        config_id = config["id"]
        assert config["enabled"] is True
        assert "session_api_key" not in config

        got = await client.get(f"/sandbox/sandbox-configs/{config_id}")
        assert got.status_code == 200
        assert got.json()["id"] == config_id

        patched = await client.patch(
            f"/sandbox/sandbox-configs/{config_id}",
            json={"enabled": False},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["enabled"] is False

        deleted = await client.delete(f"/sandbox/sandbox-configs/{config_id}")
        assert deleted.status_code == 204

        missing = await client.get(f"/sandbox/sandbox-configs/{config_id}")
        assert missing.status_code == 404

    async def test_search_and_count(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        for _ in range(3):
            resp = await client.post(
                "/sandbox/sandbox-configs",
                json={"sandbox_template_id": template_id},
            )
            assert resp.status_code == 201

        search = await client.get(
            "/sandbox/sandbox-configs",
            params={"sandbox_template_id__eq": template_id, "limit": 2},
        )
        assert search.status_code == 200
        assert len(search.json()["items"]) == 2
        assert search.json()["next_cursor"] is not None

        count = await client.get(
            "/sandbox/sandbox-configs/count",
            params={"sandbox_template_id__eq": template_id},
        )
        assert count.status_code == 200
        assert count.json()["count"] == 3

    async def test_batch_read(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        ids = []
        for _ in range(2):
            resp = await client.post(
                "/sandbox/sandbox-configs",
                json={"sandbox_template_id": template_id},
            )
            assert resp.status_code == 201
            ids.append(resp.json()["id"])

        batch = await client.get("/sandbox/sandbox-configs/batch", params={"ids": ids})
        assert batch.status_code == 200
        assert len(batch.json()["items"]) == 2

    async def test_batch_write(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        batch_resp = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"sandbox_template_id": template_id}},
                    {"op": "create", "data": {"sandbox_template_id": template_id}},
                ]
            },
        )
        assert batch_resp.status_code == 200, batch_resp.text
        items = batch_resp.json()["items"]
        assert len(items) == 2
        created_id = items[0]["id"]

        update_batch = await client.post(
            "/sandbox/sandbox-configs/batch",
            json={
                "operations": [
                    {"op": "update", "id": created_id, "data": {"enabled": True}},
                    {"op": "delete", "id": items[1]["id"]},
                ]
            },
        )
        assert update_batch.status_code == 200
        assert update_batch.json()["items"][0]["enabled"] is True
        assert update_batch.json()["items"][1] is None

    async def test_invalid_template_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404

    async def test_snapshot_on_deactivate_defaults_from_template(self, client: AsyncClient) -> None:
        template_resp = await client.post(
            "/sandbox/sandbox-templates",
            json={"docker_image_tag": f"snap-{uuid.uuid4()}", "snapshot_on_deactivate": True},
        )
        assert template_resp.status_code == 201
        template_id = template_resp.json()["id"]

        config_resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert config_resp.status_code == 201
        assert config_resp.json()["snapshot_on_deactivate"] is True

    async def test_expires_at_set(self, client: AsyncClient) -> None:
        template_id = await _create_template(client)
        expiry = datetime(2030, 1, 1, tzinfo=UTC)
        resp = await client.post(
            "/sandbox/sandbox-configs",
            json={
                "sandbox_template_id": template_id,
                "expires_at": expiry.isoformat(),
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["expires_at"] is not None
