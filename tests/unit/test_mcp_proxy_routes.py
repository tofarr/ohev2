"""Tests for the MCP JSON-RPC streaming proxy (``/mcp/{config_id}``)."""

from __future__ import annotations

import uuid

import httpx
import respx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _http_payload(display_name: str = "upstream-mcp") -> dict[str, object]:
    return {
        "display_name": display_name,
        "transport": "streamable-http",
        "url": "https://upstream.mcp.example.com/mcp",
        "headers": {"X-Upstream-Token": "header-secret"},
        "auth": {"strategy": "bearer", "value": "bearer-secret"},
        "enable_proxy": False,
    }


async def _create_http_config(client: AsyncClient, **overrides) -> dict[str, object]:
    payload = _http_payload()
    payload.update(overrides)
    response = await client.post("/mcp-server-configs", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


class TestMcpProxyPost:
    async def test_missing_config_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/mcp/{uuid.uuid4()}",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
        )
        assert resp.status_code == 404

    async def test_invalid_auth_returns_401(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        resp = await client.post(
            f"/mcp/{config['id']}",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert resp.status_code == 401

    @respx.mock
    async def test_post_forwards_jsonrpc_and_session_header(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        captured: dict[str, str] = {}

        def _capture(request: httpx.Request) -> httpx.Response:
            captured.update({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}},
                headers={"content-type": "application/json", "mcp-session-id": "sess-123"},
            )

        respx.post("https://upstream.mcp.example.com/mcp").mock(side_effect=_capture)
        resp = await client.post(
            f"/mcp/{config['id']}",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
            headers={"mcp-session-id": "incoming-sess"},
        )
        assert resp.status_code == 200
        # The stored upstream bearer credential is injected, not the caller's.
        assert captured.get("authorization") == "Bearer bearer-secret"
        # The stored upstream header is injected.
        assert captured.get("x-upstream-token") == "header-secret"
        # The caller's session id is forwarded.
        assert captured.get("mcp-session-id") == "incoming-sess"
        # The upstream session id is passed back to the caller.
        assert resp.headers.get("mcp-session-id") == "sess-123"

    @respx.mock
    async def test_post_upstream_error_passthrough(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        respx.post("https://upstream.mcp.example.com/mcp").mock(
            return_value=httpx.Response(500, json={"error": "internal"})
        )
        resp = await client.post(
            f"/mcp/{config['id']}",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
        )
        assert resp.status_code == 500

    @respx.mock
    async def test_post_sse_stream_forwarded(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        stream_body = (
            b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/initialized"}\n\n'
        )
        respx.post("https://upstream.mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                200, content=stream_body, headers={"content-type": "text/event-stream"}
            )
        )
        resp = await client.post(
            f"/mcp/{config['id']}",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert resp.status_code == 200
        assert b"notifications/initialized" in resp.content

    @respx.mock
    async def test_post_tools_call_records_usage(
        self,
        client: AsyncClient,
        session: AsyncSession,
    ) -> None:
        from openhands.ev2.mcp_server_config.mcp_usage_models import McpUsage

        config = await _create_http_config(client)
        respx.post("https://upstream.mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                },
                headers={"content-type": "application/json"},
            )
        )
        resp = await client.post(
            f"/mcp/{config['id']}",
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "search", "arguments": {"q": "hi"}},
                "id": 1,
            },
        )
        assert resp.status_code == 200
        usage = (await session.execute(select(McpUsage))).scalar_one()
        assert usage.tool_name == "search"
        assert usage.success is True


class TestMcpProxyGetDelete:
    @respx.mock
    async def test_get_opens_sse_stream(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        stream_body = b'event: message\ndata: {"jsonrpc":"2.0","method":"ping"}\n\n'
        respx.get("https://upstream.mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                200, content=stream_body, headers={"content-type": "text/event-stream"}
            )
        )
        resp = await client.get(f"/mcp/{config['id']}")
        assert resp.status_code == 200
        assert b"ping" in resp.content

    @respx.mock
    async def test_delete_terminates_session(self, client: AsyncClient) -> None:
        config = await _create_http_config(client)
        respx.delete("https://upstream.mcp.example.com/mcp").mock(return_value=httpx.Response(204))
        resp = await client.delete(f"/mcp/{config['id']}")
        assert resp.status_code == 204
