"""Route tests for the DB-backed ``/sandbox/sandbox-templates`` REST surface.

Exercises the full CRUD lifecycle, batch read/write, count, search, cursor
pagination, and validation against the embedded PostgreSQL via the ``client``
fixture. The test principal is the seeded admin user so all permission filters
resolve to ``ALL``.
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
    }
    payload.update(overrides)
    return payload


def _unique_tag() -> str:
    return f"test-{uuid.uuid4()}"


# --------------------------------------------------------------------------- #
# Search / count.
# --------------------------------------------------------------------------- #


class TestSearchAndCount:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/sandbox/sandbox-templates",
            params={"docker_image_tag__contains": _unique_tag()},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_returns_created(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        resp = await client.get(
            "/sandbox/sandbox-templates",
            params={"docker_image_tag__contains": tag},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["docker_image_tag"] == tag

    async def test_search_with_filter(self, client: AsyncClient) -> None:
        tag_a = _unique_tag()
        tag_b = _unique_tag()
        await client.post("/sandbox/sandbox-templates", json=_template_payload(tag_a))
        await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(tag_b, working_dir="/custom"),
        )
        resp = await client.get(
            "/sandbox/sandbox-templates",
            params={"docker_image_tag__contains": tag_a},
        )
        assert resp.status_code == 200
        tags = [i["docker_image_tag"] for i in resp.json()["items"]]
        assert tags == [tag_a]

    async def test_count(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        resp = await client.get(
            "/sandbox/sandbox-templates/count",
            params={"docker_image_tag__contains": tag},
        )
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_count_with_filter(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        resp = await client.get(
            "/sandbox/sandbox-templates/count",
            params={"docker_image_tag__eq": tag},
        )
        assert resp.json()["count"] == 1


# --------------------------------------------------------------------------- #
# Create / get / update / delete.
# --------------------------------------------------------------------------- #


class TestCrud:
    async def test_create_returns_201(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(tag, working_dir="/ws"),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"]
        assert body["docker_image_tag"] == tag
        assert body["working_dir"] == "/ws"

    async def test_create_then_patch(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.patch(
            f"/sandbox/sandbox-templates/{template_id}",
            json={"working_dir": "/new"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["working_dir"] == "/new"

    async def test_create_with_num_warm(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(tag, num_warm=3),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["num_warm"] == 3

    async def test_create_defaults_num_warm_to_zero(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(tag),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["num_warm"] == 0

    async def test_patch_num_warm(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.patch(
            f"/sandbox/sandbox-templates/{template_id}",
            json={"num_warm": 5},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["num_warm"] == 5

    async def test_create_rejects_negative_num_warm(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(tag, num_warm=-1),
        )
        assert resp.status_code == 422

    async def test_get_template(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.get(f"/sandbox/sandbox-templates/{template_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == template_id

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/sandbox/sandbox-templates/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_delete_template(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.delete(f"/sandbox/sandbox-templates/{template_id}")
        assert resp.status_code == 204
        assert (await client.get(f"/sandbox/sandbox-templates/{template_id}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/sandbox/sandbox-templates/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_patch_all_fields(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.patch(
            f"/sandbox/sandbox-templates/{template_id}",
            json={
                "docker_image_tag": _unique_tag(),
                "delete_after_idle_seconds": 120,
                "in_container_user_id": 1000,
                "in_container_group_id": 1000,
                "max_memory": 1024,
                "exposed_ports": [{"name": "http", "description": "web", "container_port": 8080}],
                "env_vars": {"FOO": "bar"},
                "working_dir": "/updated",
                "snapshot_dirs": ["/snap"],
                "snapshot_on_deactivate": True,
                "meta": {"key": "val"},
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["docker_image_tag"] != tag
        assert body["delete_after_idle_seconds"] == 120
        assert body["in_container_user_id"] == 1000
        assert body["in_container_group_id"] == 1000
        assert body["max_memory"] == 1024
        assert body["exposed_ports"] == [
            {"name": "http", "description": "web", "container_port": 8080}
        ]
        assert body["env_vars"] == {"FOO": "bar"}
        assert body["working_dir"] == "/updated"
        assert body["snapshot_dirs"] == ["/snap"]
        assert body["snapshot_on_deactivate"] is True
        assert body["meta"] == {"key": "val"}

    async def test_patch_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(
            f"/sandbox/sandbox-templates/{uuid.uuid4()}",
            json={"working_dir": "/new"},
        )
        assert resp.status_code == 404

    async def test_delete_template_in_use_returns_409(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        await client.post(
            "/sandbox/sandbox-configs",
            json={"sandbox_template_id": template_id},
        )
        resp = await client.delete(f"/sandbox/sandbox-templates/{template_id}")
        assert resp.status_code == 409


# --------------------------------------------------------------------------- #
# Batch read / write.
# --------------------------------------------------------------------------- #


class TestBatch:
    async def test_batch_read_aligned_with_none(self, client: AsyncClient) -> None:
        tag = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag))
        template_id = created.json()["id"]
        resp = await client.get(
            "/sandbox/sandbox-templates/batch",
            params={"ids": [template_id, str(uuid.uuid4())]},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == template_id
        assert items[1] is None

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await client.get("/sandbox/sandbox-templates/batch", params={"ids": ids})
        assert resp.status_code == 422

    async def test_batch_write_mixed(self, client: AsyncClient) -> None:
        tag_a = _unique_tag()
        tag_b = _unique_tag()
        created = await client.post("/sandbox/sandbox-templates", json=_template_payload(tag_a))
        template_id = created.json()["id"]
        resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _template_payload(tag_b)},
                    {"op": "delete", "id": template_id},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["docker_image_tag"] == tag_b
        assert items[1] is None

    async def test_batch_write_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-templates/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_write_unknown_op_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "upsert", "data": _template_payload(_unique_tag())},
                ]
            },
        )
        assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


class TestValidation:
    async def test_create_requires_docker_image_tag(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-templates", json={"working_dir": "/ws"})
        assert resp.status_code == 422

    async def test_create_rejects_non_positive_timeout(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload(_unique_tag(), delete_after_idle_seconds=0),
        )
        assert resp.status_code == 422

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400
