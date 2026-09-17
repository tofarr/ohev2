"""Route tests for the ``/sandbox-proxy/{sandbox_id}/*`` reverse proxy.

Exercises the FastAPI router end-to-end via the ASGI client with a fake
in-memory :class:`SandboxService` injected onto ``app.state``. The upstream
agent server is faked by:

* ``respx`` for HTTP/SSE/OPTIONS (canned JSON and SSE responses), and
* an in-process ``websockets`` server for the WebSocket relay test.

No Docker daemon or real container is required.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import pytest_asyncio
import respx
import websockets
from httpx import ASGITransport, AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal
from websockets.asyncio.server import serve

from openhands.ev2.config import get_config
from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.sandbox_models import ExposedUrl, SandboxStatus, SnapshotMode
from openhands.ev2.sandbox.sandbox_schemas import SandboxCreate, SandboxUpdate
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.security.security_models import Denied
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")
_SESSION_KEY = "sandbox-session-secret"
_UPSTREAM_BASE = "http://agent-server.test"


class _FakeSandboxService(SandboxService):
    """In-memory provider backing the sandbox proxy route tests."""

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._sandboxes: dict[str, DockerSandbox] = {}

    async def _list_sandboxes(self) -> list[Any]:
        return list(self._sandboxes.values())

    async def _get_sandbox(self, sandbox_id: str) -> Any:
        try:
            return self._sandboxes[sandbox_id]
        except KeyError:
            raise SandboxNotFoundError(sandbox_id) from None

    def _sandbox_from_create(self, payload: SandboxCreate) -> Any:
        raise NotImplementedError

    async def _create_sandbox(self, sandbox: Any, *, snapshot_id: str | None = None) -> Any:
        raise NotImplementedError

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Any:
        raise NotImplementedError

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        raise NotImplementedError

    async def _list_templates(self) -> list[Any]:
        return []

    async def _get_template(self, template_id: str) -> Any:
        raise SandboxTemplateNotFoundError(template_id)

    def _template_from_create(self, payload: Any) -> Any:
        raise NotImplementedError

    async def _create_template(self, sandbox: Any) -> Any:
        raise NotImplementedError

    async def _delete_template(self, template_id: str) -> None:
        raise NotImplementedError


def _active_sandbox(
    sandbox_id: str = "sb-1",
    *,
    status: SandboxStatus = SandboxStatus.ACTIVE,
    session_api_key: str | None = _SESSION_KEY,
    exposed_urls: list[ExposedUrl] | None = None,
) -> DockerSandbox:
    urls = exposed_urls if exposed_urls is not None else [
        ExposedUrl(name="agent_server", url=_UPSTREAM_BASE, port=3000),
        ExposedUrl(name="vscode", url="http://vscode.test", port=3100),
    ]
    return DockerSandbox(
        id=sandbox_id,
        sandbox_template_id="tmpl",
        status=status,
        desired_status=status,
        snapshot_mode=SnapshotMode.UNSUPPORTED,
        session_api_key=session_api_key,
        exposed_urls=urls,
    )


@pytest_asyncio.fixture
async def sandbox_service() -> _FakeSandboxService:
    return _FakeSandboxService()


@pytest_asyncio.fixture
async def client(app, sandbox_service: _FakeSandboxService) -> AsyncClient:
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
# HTTP forwarding, SSE, OPTIONS.
# --------------------------------------------------------------------------- #


class TestHttpProxy:
    async def test_missing_sandbox_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/sandbox-proxy/no-such-sandbox/api/foo")
        assert resp.status_code == 404

    @respx.mock
    async def test_get_forwards_path_query_and_session_key(
        self, client: AsyncClient, sandbox_service: _FakeSandboxService
    ) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        captured: dict[str, Any] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["url"] = str(request.url)
            captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
            return httpx.Response(200, json={"ok": True}, headers={"content-type": "application/json"})

        respx.get(f"{_UPSTREAM_BASE}/api/conversation_records").mock(side_effect=_capture)
        resp = await client.get("/sandbox-proxy/sb-1/api/conversation_records", params={"q": "hi"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        # The upstream received the proxied path and query params.
        assert captured["method"] == "GET"
        assert captured["url"].startswith(f"{_UPSTREAM_BASE}/api/conversation_records")
        assert "q=hi" in captured["url"]
        # The decrypted session key is injected upstream.
        assert captured["headers"].get("x-session-api-key") == _SESSION_KEY
        # The caller's authorization is NOT forwarded upstream.
        assert "authorization" not in captured["headers"]
        # The session key is NOT echoed back to the client.
        assert "x-session-api-key" not in {k.lower() for k in resp.headers}

    @respx.mock
    async def test_post_forwards_body_and_headers(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        captured: dict[str, Any] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            captured["content_type"] = request.headers.get("content-type")
            return httpx.Response(201, json={"created": 1})

        respx.post(f"{_UPSTREAM_BASE}/api/items").mock(side_effect=_capture)
        resp = await client.post(
            "/sandbox-proxy/sb-1/api/items",
            json={"name": "thing"},
            headers={"X-Custom": "val"},
        )
        assert resp.status_code == 201
        assert json.loads(captured["body"]) == {"name": "thing"}
        assert captured["content_type"] == "application/json"

    @respx.mock
    async def test_upstream_error_passthrough(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        respx.get(f"{_UPSTREAM_BASE}/api/oops").mock(
            return_value=httpx.Response(500, json={"error": "internal"})
        )
        resp = await client.get("/sandbox-proxy/sb-1/api/oops")
        assert resp.status_code == 500
        assert resp.json() == {"error": "internal"}

    @respx.mock
    async def test_sse_streamed_byte_for_byte(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        stream_body = (
            b'event: message\ndata: {"jsonrpc":"2.0","method":"ping"}\n\n'
            b'event: message\ndata: {"jsonrpc":"2.0","method":"pong"}\n\n'
        )
        respx.get(f"{_UPSTREAM_BASE}/api/stream").mock(
            return_value=httpx.Response(
                200, content=stream_body, headers={"content-type": "text/event-stream"}
            )
        )
        resp = await client.get("/sandbox-proxy/sb-1/api/stream")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert b"ping" in resp.content
        assert b"pong" in resp.content

    @respx.mock
    async def test_options_preflight_forwarded(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        respx.options(f"{_UPSTREAM_BASE}/api/items").mock(
            return_value=httpx.Response(
                204,
                headers={
                    "allow": "GET,POST",
                    "access-control-allow-methods": "GET,POST",
                },
            )
        )
        resp = await client.options("/sandbox-proxy/sb-1/api/items")
        assert resp.status_code == 204
        assert resp.headers.get("access-control-allow-methods") == "GET,POST"

    @respx.mock
    async def test_hop_by_hop_headers_stripped(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        respx.get(f"{_UPSTREAM_BASE}/api/x").mock(
            return_value=httpx.Response(
                200,
                json={"ok": True},
                headers={"connection": "close", "transfer-encoding": "chunked", "x-trace": "t1"},
            )
        )
        resp = await client.get("/sandbox-proxy/sb-1/api/x")
        lower = {k.lower() for k in resp.headers}
        assert "connection" not in lower
        assert "transfer-encoding" not in lower
        assert "x-trace" in lower


# --------------------------------------------------------------------------- #
# Availability / error states.
# --------------------------------------------------------------------------- #


class TestAvailability:
    async def test_not_active_returns_503(self, client: AsyncClient, sandbox_service: _FakeSandboxService) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox(status=SandboxStatus.INACTIVE)
        resp = await client.get("/sandbox-proxy/sb-1/api/foo")
        assert resp.status_code == 503

    async def test_no_agent_server_url_returns_503(
        self, client: AsyncClient, sandbox_service: _FakeSandboxService
    ) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox(exposed_urls=[])
        resp = await client.get("/sandbox-proxy/sb-1/api/foo")
        assert resp.status_code == 503

    async def test_no_session_key_returns_503(
        self, client: AsyncClient, sandbox_service: _FakeSandboxService
    ) -> None:
        sandbox_service._sandboxes["sb-1"] = _active_sandbox(session_api_key=None)
        resp = await client.get("/sandbox-proxy/sb-1/api/foo")
        assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# Permission denial (403).
# --------------------------------------------------------------------------- #


class TestPermissions:
    async def test_no_use_grant_returns_403(
        self, client: AsyncClient, sandbox_service: _FakeSandboxService, session
    ) -> None:
        # A principal with a role that explicitly denies sandbox USE.
        restricted = await _make_principal(session, email="nouse@example.com", username="nouse")
        await _assign_role(
            session,
            restricted.id,
            {"sandbox_permission": Denied()},
            role_name="nouse-sandbox",
        )
        token = create_auth_token(restricted.id)
        sandbox_service._sandboxes["sb-1"] = _active_sandbox()
        resp = await client.get(
            "/sandbox-proxy/sb-1/api/foo",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# WebSocket relay.
# --------------------------------------------------------------------------- #


class TestWebSocketProxy:
    """Drive the WebSocket route via raw ASGI on the test's event loop.

    Using the raw ASGI interface (scope/receive/send) instead of Starlette's
    sync ``TestClient`` keeps the WebSocket handler, its DB auth dependency, and
    the in-process upstream WS server on a single event loop — avoiding the
    cross-loop asyncpg connection issue inherent to the portal-based TestClient.
    """

    @staticmethod
    def _ws_scope(sandbox_id: str, path: str, token: str) -> dict[str, Any]:
        return {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "ws",
            "path": f"/sandbox-proxy/{sandbox_id}/{path}",
            "raw_path": f"/sandbox-proxy/{sandbox_id}/{path}".encode(),
            "query_string": b"",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "subprotocols": [],
            "state": {},
            "extensions": {},
        }

    async def test_frames_relayed_bidirectionally_and_key_injected(
        self, app, sandbox_service: _FakeSandboxService
    ) -> None:
        app.state.sandbox_service = sandbox_service
        captured_headers: dict[str, str] = {}

        async def _echo_handler(upstream_ws: websockets.asyncio.server.ServerConnection) -> None:
            captured_headers.update({k.lower(): v for k, v in upstream_ws.request.headers.items()})
            async for msg in upstream_ws:
                await upstream_ws.send(f"echo:{msg}")

        server = await serve(_echo_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        # Repoint the sandbox's agent_server URL at the in-process WS server.
        sandbox_service._sandboxes["sb-1"] = _active_sandbox(
            exposed_urls=[ExposedUrl(name="agent_server", url=f"http://127.0.0.1:{port}", port=port)],
        )
        try:
            token = create_auth_token(_TEST_USER_ID)
            scope = self._ws_scope("sb-1", "ws", token)

            client_outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
            await client_outbox.put({"type": "websocket.connect"})
            await client_outbox.put({"type": "websocket.receive", "text": "hello-upstream"})
            client_inbox: list[dict[str, Any]] = []
            echo_done = asyncio.Event()

            async def receive() -> dict[str, Any]:
                return await client_outbox.get()

            async def send(message: dict[str, Any]) -> None:
                t = message["type"]
                if t in ("websocket.receive", "websocket.send") and message.get("text") is not None:
                    client_inbox.append(message)
                    echo_done.set()
                elif t == "websocket.close":
                    pass

            # Drive the ASGI app concurrently so we can feed the disconnect
            # after the echo round-trips (avoids cancelling the upstream pump
            # before the echo is delivered).
            app_task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(echo_done.wait(), timeout=5)
            await client_outbox.put({"type": "websocket.disconnect", "code": 1000})
            await asyncio.wait_for(app_task, timeout=5)
        finally:
            server.close()
            await server.wait_closed()

        assert captured_headers.get("x-session-api-key") == _SESSION_KEY
        texts = [m.get("text") for m in client_inbox if m.get("text") is not None]
        assert "echo:hello-upstream" in texts

    async def test_missing_sandbox_closes_ws(
        self, app, sandbox_service: _FakeSandboxService
    ) -> None:
        app.state.sandbox_service = sandbox_service
        token = create_auth_token(_TEST_USER_ID)
        scope = self._ws_scope("no-such", "ws", token)

        async def receive() -> dict[str, Any]:
            return {"type": "websocket.connect"}

        closed: dict[str, Any] = {}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "websocket.close":
                closed["code"] = message.get("code")

        await app(scope, receive, send)
        # 404 → 4404 close code (pre-accept failure surfaces as a close).
        assert closed.get("code") == 4404
