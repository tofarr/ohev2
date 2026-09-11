"""Route tests for the DB-backed ``/sandbox/sandbox-templates`` REST surface.

Exercises the full CRUD lifecycle (create, read, update, delete), batch
read/write, count, search, and cursor pagination against the embedded
PostgreSQL via the ``client`` fixture. The test principal is the seeded admin
user so all permission filters resolve to ``ALL``.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient


def _template_payload(
    docker_image_tag: str = "ghcr.io/org/agent-server:latest", **overrides: object
) -> dict[str, object]:
    payload: dict[str, object] = {
        "docker_image_tag": docker_image_tag,
        "working_dir": "/home/openhands",
        "env_vars": {"FOO": "bar"},
        "exposed_ports": [{"name": "http", "description": "HTTP server", "container_port": 8080}],
        "snapshot_dirs": ["/home/openhands"],
    }
    payload.update(overrides)
    return payload


class TestSandboxTemplateRoutes:
    async def test_crud_lifecycle(self, client: AsyncClient) -> None:
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload())
        assert created.status_code == 201, created.text
        template = created.json()
        template_id = template["id"]
        assert template["docker_image_tag"] == "ghcr.io/org/agent-server:latest"
        assert template["env_vars"] == {"FOO": "bar"}

        got = await client.get(f"/sandbox/sandbox-templates/{template_id}")
        assert got.status_code == 200
        assert got.json()["id"] == template_id

        patched = await client.patch(
            f"/sandbox/sandbox-templates/{template_id}",
            json={"docker_image_tag": "ghcr.io/org/agent-server:v2", "env_vars": {"BAZ": "qux"}},
        )
        assert patched.status_code == 200, patched.text
        patched_data = patched.json()
        assert patched_data["docker_image_tag"] == "ghcr.io/org/agent-server:v2"
        assert patched_data["env_vars"] == {"BAZ": "qux"}

        deleted = await client.delete(f"/sandbox/sandbox-templates/{template_id}")
        assert deleted.status_code == 204

        missing = await client.get(f"/sandbox/sandbox-templates/{template_id}")
        assert missing.status_code == 404

    async def test_search_pagination_and_count(self, client: AsyncClient) -> None:
        tag = f"search-{uuid.uuid4()}"
        for i in range(3):
            resp = await client.post(
                "/sandbox/sandbox-templates",
                json=_template_payload(f"{tag}:{i}"),
            )
            assert resp.status_code == 201, resp.text

        search = await client.get(
            "/sandbox/sandbox-templates",
            params={"limit": 2, "docker_image_tag__contains": tag},
        )
        assert search.status_code == 200
        data = search.json()
        assert len(data["items"]) == 2
        assert data["next_cursor"] is not None

        next_page = await client.get(
            "/sandbox/sandbox-templates",
            params={"limit": 2, "docker_image_tag__contains": tag, "cursor": data["next_cursor"]},
        )
        assert next_page.status_code == 200
        assert len(next_page.json()["items"]) == 1

        count = await client.get(
            "/sandbox/sandbox-templates/count",
            params={"docker_image_tag__contains": tag},
        )
        assert count.status_code == 200
        assert count.json()["count"] == 3

    async def test_batch_read(self, client: AsyncClient) -> None:
        ids = []
        for i in range(2):
            resp = await client.post(
                "/sandbox/sandbox-templates",
                json=_template_payload(f"batch-{uuid.uuid4()}:{i}"),
            )
            assert resp.status_code == 201
            ids.append(resp.json()["id"])

        batch = await client.get("/sandbox/sandbox-templates/batch", params={"ids": ids})
        assert batch.status_code == 200
        assert len(batch.json()["items"]) == 2

        missing_batch = await client.get(
            "/sandbox/sandbox-templates/batch",
            params={"ids": [str(uuid.uuid4())]},
        )
        assert missing_batch.status_code == 200
        assert missing_batch.json()["items"] == [None]

    async def test_batch_write(self, client: AsyncClient) -> None:
        tag = f"bw-{uuid.uuid4()}"
        batch_resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _template_payload(f"{tag}:1")},
                    {"op": "create", "data": _template_payload(f"{tag}:2")},
                ]
            },
        )
        assert batch_resp.status_code == 200, batch_resp.text
        items = batch_resp.json()["items"]
        assert len(items) == 2
        created_id = items[0]["id"]

        delete_batch = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={"operations": [{"op": "delete", "id": created_id}]},
        )
        assert delete_batch.status_code == 200
        assert delete_batch.json()["items"] == [None]

    async def test_invalid_cursor(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400

    async def test_batch_read_limit(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await client.get("/sandbox/sandbox-templates/batch", params={"ids": ids})
        assert resp.status_code == 422

    async def test_delete_restricted_by_config(
        self, client: AsyncClient, user_id: uuid.UUID
    ) -> None:
        template_resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(f"restricted-{uuid.uuid4()}"),
        )
        assert template_resp.status_code == 201
        template_id = template_resp.json()["id"]

        config_resp = await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        assert config_resp.status_code == 201, config_resp.text

        delete_resp = await client.delete(f"/sandbox/sandbox-templates/{template_id}")
        assert delete_resp.status_code == 409
