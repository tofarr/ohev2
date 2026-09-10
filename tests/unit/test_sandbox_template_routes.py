"""Route tests for the ``/sandbox/sandbox-templates`` REST surface.

These exercise the FastAPI router end-to-end via the ASGI client with a fake
in-memory :class:`SandboxService` injected onto ``app.state`` (the same place
the lifespan puts the real Docker service). No Docker daemon or DB-backed
template state is required; the test principal is the seeded admin user so all
permission filters resolve to ``ALL``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openhands.ev2.config import get_config
from openhands.ev2.sandbox.sandbox_models import DockerSandboxTemplate, SandboxTemplate
from openhands.ev2.sandbox.sandbox_schemas import SandboxTemplateCreate
from openhands.ev2.sandbox.sandbox_service import (
    SandboxService,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


class _FakeSandboxService(SandboxService):
    """In-memory provider backing the router tests."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._templates: dict[str, SandboxTemplate] = {}

    async def _list_templates(self) -> list[SandboxTemplate]:
        return list(self._templates.values())

    async def _get_template(self, template_id: str) -> SandboxTemplate:
        try:
            return self._templates[template_id]
        except KeyError:
            raise SandboxTemplateNotFoundError(template_id) from None

    def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
        return DockerSandboxTemplate(
            id=payload.id,
            command=payload.command,
            initial_env=payload.initial_env,
            working_dir=payload.working_dir,
            idle_pause_seconds=payload.idle_pause_seconds,
            paused_delete_seconds=payload.paused_delete_seconds,
            max_age_seconds=payload.max_age_seconds,
            max_memory=payload.max_memory,
        )

    async def _create_template(self, template: SandboxTemplate) -> SandboxTemplate:
        if template.id in self._templates:
            raise SandboxTemplateConflictError(template.id)
        self._templates[template.id] = template
        return template

    async def _delete_template(self, template_id: str) -> None:
        if template_id not in self._templates:
            raise SandboxTemplateNotFoundError(template_id) from None
        del self._templates[template_id]

    # The sandbox hooks are not exercised by the template-route tests but the
    # abstract base requires concrete implementations.
    async def _list_sandboxes(self) -> list[Any]:
        return []

    async def _get_sandbox(self, sandbox_id: str) -> Any:
        raise NotImplementedError

    def _sandbox_from_create(self, payload: Any) -> Any:
        raise NotImplementedError

    async def _create_sandbox(self, sandbox: Any) -> Any:
        raise NotImplementedError

    async def _update_sandbox(self, sandbox_id: str, payload: Any) -> Any:
        raise NotImplementedError

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        raise NotImplementedError


def _template_payload(template_id: str = "img-a", **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": template_id}
    payload.update(overrides)
    return payload


@pytest_asyncio.fixture
async def sandbox_service() -> _FakeSandboxService:
    return _FakeSandboxService()


@pytest_asyncio.fixture
async def client(app, sandbox_service: _FakeSandboxService) -> AsyncClient:
    """ASGI client with a fake sandbox service on ``app.state``.

    The default ``client`` fixture builds its client from ``app`` but does not
    run the lifespan, so ``app.state.sandbox_service`` is unset; we set it
    directly here so ``get_sandbox_service`` resolves our in-memory fake.
    """
    app.state.sandbox_service = sandbox_service
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
# Service availability.
# --------------------------------------------------------------------------- #


async def test_get_sandbox_service_unavailable_when_unset(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No sandbox_service on app.state -> the dependency returns 503 once auth
    # passes (the seeded admin principal authenticates via a JWE token).
    from openhands.ev2.util.auth_token import create_auth_token

    get_config.cache_clear()
    token = create_auth_token(_TEST_USER_ID)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        resp = await ac.get("/sandbox/sandbox-templates")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# Search / count.
# --------------------------------------------------------------------------- #


class TestSearchAndCount:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_returns_created(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.get("/sandbox/sandbox-templates")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == "img-a"

    async def test_search_with_filter(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload("img-b", idle_pause_seconds=10),
        )
        resp = await client.get("/sandbox/sandbox-templates?id__contains=a")
        assert resp.status_code == 200
        assert [i["id"] for i in resp.json()["items"]] == ["img-a"]

    async def test_count(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.get("/sandbox/sandbox-templates/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_count_with_filter(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.get("/sandbox/sandbox-templates/count?id__eq=img-a")
        assert resp.json()["count"] == 1


# --------------------------------------------------------------------------- #
# Create / get / update / delete.
# --------------------------------------------------------------------------- #


class TestCrud:
    async def test_create_returns_201(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload("img-a", working_dir="/ws"),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"] == "img-a"
        assert body["working_dir"] == "/ws"

    async def test_create_conflict_returns_409(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        assert resp.status_code == 409

    async def test_get_template(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.get("/sandbox/sandbox-templates/img-a")
        assert resp.status_code == 200
        assert resp.json()["id"] == "img-a"

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates/nope")
        assert resp.status_code == 404

    async def test_update_template_not_supported(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.patch(
            "/sandbox/sandbox-templates/img-a",
            json={"working_dir": "/new"},
        )
        assert resp.status_code == 405

    async def test_delete_template(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.delete("/sandbox/sandbox-templates/img-a")
        assert resp.status_code == 204
        assert (await client.get("/sandbox/sandbox-templates/img-a")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete("/sandbox/sandbox-templates/nope")
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Batch read / write.
# --------------------------------------------------------------------------- #


class TestBatch:
    async def test_batch_read_aligned_with_none(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.get("/sandbox/sandbox-templates/batch?ids=img-a&ids=missing")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == "img-a"
        assert items[1] is None

    async def test_batch_read_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox/sandbox-templates/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_read_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/sandbox/sandbox-templates/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_write_mixed(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _template_payload("img-b")},
                    {"op": "delete", "id": "img-a"},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["id"] == "img-b"
        assert items[1] is None

    async def test_batch_write_empty_ops_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-templates/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_write_conflict_maps_to_409(self, client: AsyncClient) -> None:
        await client.post("/sandbox/sandbox-templates", json=_template_payload("img-a"))
        resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "create", "data": _template_payload("img-a")},
                ]
            },
        )
        assert resp.status_code == 409

    async def test_batch_write_unknown_op_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-templates/batch",
            json={
                "operations": [
                    {"op": "upsert", "data": _template_payload("img-a")},
                ]
            },
        )
        assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


class TestValidation:
    async def test_create_requires_id(self, client: AsyncClient) -> None:
        resp = await client.post("/sandbox/sandbox-templates", json={})
        assert resp.status_code == 422

    async def test_create_rejects_non_positive_timeout(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/sandbox/sandbox-templates",
            json=_template_payload("img-a", idle_pause_seconds=0),
        )
        assert resp.status_code == 422
