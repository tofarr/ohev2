"""Route tests for the DB-backed ``/sandbox/sandbox-snapshots`` REST surface.

Exercises the full CRUD lifecycle (create from sandbox, create from file, get,
download, delete), batch read/write, count, search, and validation against the
embedded PostgreSQL via the ``client`` fixture. Artifact operations (capture,
import, stream, delete-artifact) are delegated to a fake
:class:`SandboxService` on ``app.state``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest_asyncio
from httpx import AsyncClient

from openhands.ev2.sandbox.sandbox_service import SandboxService


class _FakeArtifactService(SandboxService):
    """Minimal provider that supports snapshot artifact operations only."""

    async def capture_snapshot(
        self, sandbox_id: str, *, sandbox_perm_filter: Any = None
    ) -> tuple[str, int | None]:
        return f"artifact://{sandbox_id}", 42

    async def import_snapshot_file(
        self, file_data: bytes | None, *, schema_type: str | None = None
    ) -> tuple[str, int | None]:
        return f"artifact://import-{schema_type}", len(file_data or b"")

    async def stream_snapshot(self, snapshot_id: str) -> Any:
        async def _gen() -> Any:
            yield b"fake-tar-content"

        return _gen()

    async def delete_snapshot_artifact(self, snapshot_id: str) -> None:
        pass

    # Required ABC stubs — not exercised by snapshot route tests.
    async def _list_templates(self) -> list[Any]:
        return []

    async def _get_template(self, template_id: str) -> Any:
        raise NotImplementedError

    def _template_from_create(self, payload: Any) -> Any:
        raise NotImplementedError

    async def _create_template(self, template: Any) -> Any:
        raise NotImplementedError

    async def _delete_template(self, template_id: str) -> None:
        raise NotImplementedError

    async def _list_sandboxes(self) -> list[Any]:
        return []

    async def _get_sandbox(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    def _sandbox_from_create(self, payload: Any) -> Any:
        raise NotImplementedError

    async def _create_sandbox(self, sandbox: Any, *, snapshot_id: str | None = None) -> Any:
        raise NotImplementedError

    async def _update_sandbox(self, sandbox_id: str, payload: Any) -> Any:
        raise NotImplementedError

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        raise NotImplementedError


@pytest_asyncio.fixture
async def snapshot_client(app, client: AsyncClient) -> AsyncClient:
    """Augment the DB-backed ``client`` with a fake sandbox service for artifacts."""
    app.state.sandbox_service = _FakeArtifactService()
    return client


async def _create_template(client: AsyncClient) -> str:
    """Create a sandbox template and return its UUID (needed for snapshot FK)."""
    tag = f"snap-{uuid.uuid4()}"
    resp = await client.post(
        "/sandbox/sandbox-templates",
        json={"docker_image_tag": tag, "working_dir": "/home/openhands"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# --------------------------------------------------------------------------- #
# Search / count.
# --------------------------------------------------------------------------- #


class TestSearchAndCount:
    async def test_search_empty(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.get("/sandbox/sandbox-snapshots")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None

    async def test_search_returns_created(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={
                "sandbox_template_id": template_id,
                "schema_type": "docker-workspace-tar-v1",
            },
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        assert create.status_code == 201, create.text
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.get("/sandbox/sandbox-snapshots")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        assert any(i["id"] == snapshot_id for i in items)

    async def test_search_pagination(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        for _ in range(3):
            resp = await snapshot_client.post(
                "/sandbox/sandbox-snapshots",
                data={"sandbox_template_id": template_id, "schema_type": "v1"},
                files={"file": ("ws.tar", b"fake", "application/octet-stream")},
            )
            assert resp.status_code == 201, resp.text
        page = await snapshot_client.get("/sandbox/sandbox-snapshots?limit=2")
        assert page.status_code == 200
        body = page.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_count(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        resp = await snapshot_client.get("/sandbox/sandbox-snapshots/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_count_with_filter(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.get(f"/sandbox/sandbox-snapshots/count?id__eq={snapshot_id}")
        assert resp.json()["count"] == 1


# --------------------------------------------------------------------------- #
# Create / get / download / delete.
# --------------------------------------------------------------------------- #


class TestCrud:
    async def test_create_from_file(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "docker-workspace-tar-v1"},
            files={"file": ("image.tar", b"fake-tar", "application/octet-stream")},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"]
        assert body["download_url"] == f"/sandbox/sandbox-snapshots/{body['id']}/download"
        assert body["schema"] == "docker-workspace-tar-v1"

    async def test_create_from_sandbox(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={
                "sandbox_template_id": template_id,
                "sandbox_id": str(uuid.uuid4()),
                "schema_type": "docker-workspace-tar-v1",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"]
        assert body["sandbox_id"] is not None

    async def test_create_does_not_accept_caller_id(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={
                "sandbox_template_id": template_id,
                "schema_type": "v1",
                "id": "caller-chosen",
            },
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["id"] != "caller-chosen"

    async def test_get_snapshot(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == snapshot_id

    async def test_get_missing_returns_404(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.get(f"/sandbox/sandbox-snapshots/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_download_snapshot(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}/download")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/gzip"
        assert "attachment" in resp.headers["content-disposition"]

    async def test_download_missing_returns_404(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.get(f"/sandbox/sandbox-snapshots/{uuid.uuid4()}/download")
        assert resp.status_code == 404

    async def test_delete_snapshot(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.delete(f"/sandbox/sandbox-snapshots/{snapshot_id}")
        assert resp.status_code == 204
        assert (
            await snapshot_client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}")
        ).status_code == 404

    async def test_delete_missing_returns_404(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.delete(f"/sandbox/sandbox-snapshots/{uuid.uuid4()}")
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Batch read / write.
# --------------------------------------------------------------------------- #


class TestBatch:
    async def test_batch_read_aligned_with_none(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.get(
            "/sandbox/sandbox-snapshots/batch",
            params={"ids": [snapshot_id, str(uuid.uuid4())]},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == snapshot_id
        assert items[1] is None

    async def test_batch_read_empty(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.get("/sandbox/sandbox-snapshots/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many_returns_422(self, snapshot_client: AsyncClient) -> None:
        ids = [str(uuid.uuid4()) for _ in range(101)]
        resp = await snapshot_client.get("/sandbox/sandbox-snapshots/batch", params={"ids": ids})
        assert resp.status_code == 422

    async def test_batch_write_delete(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        create = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id, "schema_type": "v1"},
            files={"file": ("ws.tar", b"fake", "application/octet-stream")},
        )
        snapshot_id = create.json()["id"]
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots/batch",
            json={"operations": [{"op": "delete", "id": snapshot_id}]},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["items"] == []

    async def test_batch_write_empty_ops_rejected(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots/batch", json={"operations": []}
        )
        assert resp.status_code == 422

    async def test_batch_write_delete_missing_maps_to_404(
        self, snapshot_client: AsyncClient
    ) -> None:
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots/batch",
            json={"operations": [{"op": "delete", "id": str(uuid.uuid4())}]},
        )
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


class TestValidation:
    async def test_create_requires_template_id(self, snapshot_client: AsyncClient) -> None:
        resp = await snapshot_client.post("/sandbox/sandbox-snapshots")
        assert resp.status_code == 422

    async def test_create_requires_source(self, snapshot_client: AsyncClient) -> None:
        template_id = await _create_template(snapshot_client)
        resp = await snapshot_client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_template_id": template_id},
        )
        assert resp.status_code == 422
