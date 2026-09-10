"""Route tests for the ``/sandbox/sandbox-snapshots`` REST surface.

Exercises the FastAPI router end-to-end via the ASGI client with a fake
in-memory :class:`SandboxService` that supports snapshots. No Docker daemon
or DB-backed state is required.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openhands.ev2.config import get_config
from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox, DockerSandboxSnapshot
from openhands.ev2.sandbox.sandbox_models import SandboxStatus, SnapshotMode
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxSnapshotCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


class _FakeSnapshotService(SandboxService):
    """In-memory provider with snapshot support."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._sandboxes: dict[str, DockerSandbox] = {}
        self._snapshots: dict[str, DockerSandboxSnapshot] = {}
        self._sandbox_counter = 0

    def _next_sandbox_id(self) -> str:
        self._sandbox_counter += 1
        return f"sandbox-{self._sandbox_counter}"

    # -- Sandbox hooks --
    async def _list_sandboxes(self) -> list[Any]:
        return list(self._sandboxes.values())

    async def _get_sandbox(self, sandbox_id: str) -> Any:
        try:
            return self._sandboxes[sandbox_id]
        except KeyError:
            raise SandboxNotFoundError(sandbox_id) from None

    def _sandbox_from_create(self, payload: SandboxCreate) -> Any:
        return DockerSandbox(
            sandbox_template_id=payload.sandbox_template_id,
            status=SandboxStatus.ACTIVE,
            desired_status=SandboxStatus.ACTIVE,
            snapshot_mode=SnapshotMode.MANUAL,
        )

    async def _create_sandbox(self, sandbox: Any) -> Any:
        sandbox_id = self._next_sandbox_id()
        sandbox.id = sandbox_id
        self._sandboxes[sandbox_id] = sandbox
        return sandbox

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Any:
        return self._sandboxes[sandbox_id]

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        self._sandboxes.pop(sandbox_id, None)

    # -- Snapshot hooks --
    async def _list_snapshots(self) -> list[Any]:
        return list(self._snapshots.values())

    async def _get_snapshot(self, snapshot_id: str) -> Any:
        try:
            return self._snapshots[snapshot_id]
        except KeyError:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None

    async def _snapshot_from_sandbox(self, payload: SandboxSnapshotCreate, sandbox: Any) -> Any:
        return DockerSandboxSnapshot(
            image_id=f"image-{sandbox.id}",
            sandbox_id=sandbox.id,
        )

    async def _snapshot_from_file(self, payload: SandboxSnapshotCreate) -> Any:
        return DockerSandboxSnapshot(
            image_id="image-file",
            sandbox_id=None,
        )

    async def _create_snapshot(self, snapshot: Any, payload: SandboxSnapshotCreate) -> Any:
        snapshot_id = self._next_sandbox_id()
        snapshot.id = snapshot_id
        if snapshot.image_id:
            snapshot.image_id = f"image-{snapshot_id}"
        if snapshot.id in self._snapshots:
            raise SandboxSnapshotConflictError(snapshot.id)
        self._snapshots[snapshot.id] = snapshot
        return snapshot

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        if snapshot_id not in self._snapshots:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        del self._snapshots[snapshot_id]

    async def stream_snapshot(self, snapshot_id: str) -> Any:
        async def _gen() -> Any:
            yield b"fake-tar-content"

        return _gen()

    # Template hooks — not exercised here but required by the ABC.
    async def _list_templates(self) -> list[Any]:
        return []

    async def _get_template(self, template_id: str) -> Any:
        raise SandboxTemplateNotFoundError(template_id)

    def _template_from_create(self, payload: Any) -> Any:
        raise NotImplementedError

    async def _create_template(self, template: Any) -> Any:
        raise NotImplementedError

    async def _delete_template(self, template_id: str) -> None:
        raise NotImplementedError


@pytest_asyncio.fixture
async def snapshot_service() -> _FakeSnapshotService:
    svc = _FakeSnapshotService()
    # Pre-create a sandbox so snapshot-from-sandbox tests don't need a prior create.
    svc._sandboxes["sb-1"] = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img-a",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        snapshot_mode=SnapshotMode.MANUAL,
    )
    return svc


@pytest_asyncio.fixture
async def client(app, snapshot_service: _FakeSnapshotService) -> AsyncClient:
    app.state.sandbox_service = snapshot_service
    get_config.cache_clear()
    token = create_auth_token(_TEST_USER_ID)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


# --------------------------------------------------------------------------- #
# Search / count.
# --------------------------------------------------------------------------- #


class TestSearchAndCount:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-snapshots")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None

    async def test_search_returns_created(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.get("/sandbox/sandbox-snapshots")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == snapshot_id

    async def test_search_with_filter(self, client: AsyncClient) -> None:
        await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        resp = await client.get("/sandbox/sandbox-snapshots?id__contains=nope")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for _ in range(3):
            await client.post(
                "/sandbox/sandbox-snapshots",
                data={"sandbox_id": "sb-1"},
            )
        resp = await client.get("/sandbox/sandbox-snapshots?limit=2")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_count(self, client: AsyncClient) -> None:
        await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        resp = await client.get("/sandbox/sandbox-snapshots/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_count_with_filter(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.get(f"/sandbox/sandbox-snapshots/count?id__eq={snapshot_id}")
        assert resp.json()["count"] == 1


# --------------------------------------------------------------------------- #
# Create / get / download / delete.
# --------------------------------------------------------------------------- #


class TestCrud:
    async def test_create_from_sandbox_returns_201(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"]
        assert body["download_url"] == f"/sandbox/sandbox-snapshots/{body['id']}/download"

    async def test_create_does_not_accept_caller_id(self, client: AsyncClient) -> None:
        # The id is generated by the service, not supplied by the caller; an
        # ``id`` form field is simply ignored (not a 422 — FastAPI drops extra
        # form fields by default).
        resp = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"id": "caller-chosen", "sandbox_id": "sb-1"},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["id"] != "caller-chosen"

    async def test_create_from_file(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"schema_type": "docker-image-tar"},
            files={"file": ("image.tar", b"fake-tar", "application/octet-stream")},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["id"]

    async def test_get_snapshot(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == snapshot_id

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-snapshots/nope")
        assert resp.status_code == 404

    async def test_download_snapshot(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}/download")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/x-tar"
        assert "attachment" in resp.headers["content-disposition"]

    async def test_download_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-snapshots/nope/download")
        assert resp.status_code == 404

    async def test_delete_snapshot(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.delete(f"/sandbox/sandbox-snapshots/{snapshot_id}")
        assert resp.status_code == 204
        assert (await client.get(f"/sandbox/sandbox-snapshots/{snapshot_id}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete("/sandbox/sandbox-snapshots/nope")
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Batch read / write.
# --------------------------------------------------------------------------- #


class TestBatch:
    async def test_batch_read_aligned_with_none(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.get(f"/sandbox/sandbox-snapshots/batch?ids={snapshot_id}&ids=missing")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == snapshot_id
        assert items[1] is None

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-snapshots/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/sandbox/sandbox-snapshots/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_write_delete(self, client: AsyncClient) -> None:
        create = await client.post(
            "/sandbox/sandbox-snapshots",
            data={"sandbox_id": "sb-1"},
        )
        snapshot_id = create.json()["id"]
        resp = await client.post(
            "/sandbox/sandbox-snapshots/batch",
            json={
                "operations": [
                    {"op": "delete", "id": snapshot_id},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["items"] == [None]

    async def test_batch_write_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-snapshots/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_write_delete_missing_maps_to_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-snapshots/batch",
            json={
                "operations": [
                    {"op": "delete", "id": "nope"},
                ]
            },
        )
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


class TestValidation:
    async def test_create_requires_source(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-snapshots")
        assert resp.status_code == 422
