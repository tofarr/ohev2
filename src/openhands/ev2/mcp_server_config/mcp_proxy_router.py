"""Streaming JSON-RPC proxy for MCP server configs.

A single ``POST /mcp/{config_id}`` endpoint (plus ``GET``/``DELETE`` for the
streamable-http lifecycle) that authenticates the caller through the standard
auth dependencies, authorizes ``USE`` on the stored MCP server config, then
forwards the raw JSON-RPC request to the stored upstream URL with the stored
upstream auth/headers injected. The caller never receives the upstream
credentials; it authenticates with its own user-scoped credential.

The proxy is transport-agnostic within the MCP streamable-http family: it
forwards JSON-RPC requests, streams SSE responses back byte-for-byte, and
passes ``mcp-session-id`` / ``mcp-protocol-version`` headers both ways.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    depends_user_id,
)
from openhands.ev2.db import SessionDep
from openhands.ev2.mcp_server_config.mcp_server_config_models import MCPServerConfig
from openhands.ev2.mcp_server_config.mcp_server_config_service import (
    MCPServerConfigNotFoundError,
    MCPServerConfigService,
)
from openhands.ev2.mcp_server_config.mcp_usage_service import McpUsageService
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mcp", tags=["mcp-proxy"], include_in_schema=False)

# ``USE`` permission on the MCP server config — resolved once at import time.
_mcp_use_dep = depends_permissions(MCPServerConfig, Action.USE)

# MCP streamable-http protocol headers (RFC 2025-06-18).
_SESSION_ID_HEADER = "mcp-session-id"
_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)


@router.post("/{config_id}", response_model=None)
async def mcp_proxy_post(
    config_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(_mcp_use_dep),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> Response | StreamingResponse:
    """Forward a JSON-RPC POST to the stored upstream MCP server."""
    service = MCPServerConfigService(session, perm_filter)
    config = await _load_config(service, config_id)
    upstream_url, upstream_headers = _resolve_upstream(request, config)
    body = await request.body()

    client = httpx.AsyncClient(timeout=None)
    upstream = await client.send(
        client.build_request(
            "POST",
            upstream_url,
            content=body,
            headers=upstream_headers,
            params=request.query_params,
        ),
        stream=True,
    )
    if upstream.status_code >= 400:
        content = await upstream.aread()
        await upstream.aclose()
        await client.aclose()
        return Response(
            content=content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )
    content_type = upstream.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        return StreamingResponse(
            _sse_proxy(client, upstream, session, user_id, config.id),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_passthrough_headers(upstream),
        )
    # JSON (or 202 Accepted with no body) — read fully and record usage.
    content = await upstream.aread()
    await upstream.aclose()
    await client.aclose()
    await _maybe_record_jsonrpc_usage(session, user_id, config.id, body, content)
    return Response(
        content=content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
        headers=_passthrough_headers(upstream),
    )


@router.get("/{config_id}", response_model=None)
async def mcp_proxy_get(
    config_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(_mcp_use_dep),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> Response | StreamingResponse:
    """Open a server-initiated stream (GET) on the upstream MCP session."""
    service = MCPServerConfigService(session, perm_filter)
    config = await _load_config(service, config_id)
    upstream_url, upstream_headers = _resolve_upstream(request, config)

    client = httpx.AsyncClient(timeout=None)
    upstream = await client.send(
        client.build_request("GET", upstream_url, headers=upstream_headers),
        stream=True,
    )
    if upstream.status_code >= 400:
        content = await upstream.aread()
        await upstream.aclose()
        await client.aclose()
        return Response(
            content=content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )
    return StreamingResponse(
        _sse_passthrough(client, upstream),
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "text/event-stream"),
        headers=_passthrough_headers(upstream),
    )


@router.delete("/{config_id}", response_model=None)
async def mcp_proxy_delete(
    config_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    perm_filter: Annotated[
        SearchFilter[MCPServerConfig],
        Depends(_mcp_use_dep),
    ],
    user_id: Annotated[uuid.UUID, Depends(depends_user_id)],
) -> Response:
    """Terminate an upstream MCP session."""
    service = MCPServerConfigService(session, perm_filter)
    config = await _load_config(service, config_id)
    upstream_url, upstream_headers = _resolve_upstream(request, config)
    async with httpx.AsyncClient(timeout=None) as client:
        upstream = await client.delete(upstream_url, headers=upstream_headers)
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
        headers=_passthrough_headers(upstream),
    )


async def _load_config(
    service: MCPServerConfigService,
    config_id: uuid.UUID,
) -> MCPServerConfig:
    try:
        return await service.get(config_id)
    except MCPServerConfigNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server config not found: {exc}",
        ) from exc


def _resolve_upstream(
    request: Request,
    config: MCPServerConfig,
) -> tuple[str, dict[str, str]]:
    """Resolve the upstream URL and build headers with stored auth injected."""
    from openhands.ev2.encryption.encryption_service import get_encryption_service

    server = config.to_mcp_server(
        get_encryption_service(),
        proxy_url=None,
        use_proxy=False,
    )
    upstream_url = server.url
    if upstream_url is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="MCP server config has no upstream url.",
        )
    return upstream_url, _upstream_headers(request, server)


def _upstream_headers(request: Request, server: Any) -> dict[str, str]:
    headers: dict[str, str] = {
        "accept": request.headers.get("accept", "application/json, text/event-stream"),
        "content-type": "application/json",
    }
    for name in (_SESSION_ID_HEADER, _PROTOCOL_VERSION_HEADER):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    if server.auth is not None:
        auth_headers = server.auth.to_http_headers()
        if auth_headers:
            headers.update(auth_headers)
    if server.headers:
        headers.update({k: v.get_secret_value() for k, v in server.headers.items()})
    return headers


def _passthrough_headers(upstream: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in upstream.headers.items():
        if name.lower() not in _HOP_BY_HOP:
            out[name] = value
    return out


async def _sse_passthrough(
    client: httpx.AsyncClient,
    upstream: httpx.Response,
) -> AsyncIterator[bytes]:
    try:
        async for chunk in upstream.aiter_bytes():
            yield chunk
    finally:
        await upstream.aclose()
        await client.aclose()


async def _sse_proxy(
    client: httpx.AsyncClient,
    upstream: httpx.Response,
    session: AsyncSession,
    creator_id: uuid.UUID,
    config_id: uuid.UUID,
) -> AsyncIterator[bytes]:
    """Stream the upstream SSE response and best-effort record tool-call usage."""
    buffer = ""
    tool_name: str | None = None
    request_id: str | None = None
    started = time.monotonic()
    try:
        async for chunk in upstream.aiter_bytes():
            buffer, parsed = _parse_sse_for_toolcall(buffer, chunk)
            if parsed is not None:
                tn, rid = parsed
                if tool_name is None:
                    tool_name = tn
                if request_id is None:
                    request_id = rid
            yield chunk
    finally:
        await upstream.aclose()
        await client.aclose()
        if tool_name is not None:
            duration_ms = int((time.monotonic() - started) * 1000)
            row = await McpUsageService(session).record_usage(
                creator_id=creator_id,
                mcp_server_config_id=config_id,
                tool_name=tool_name,
                duration_ms=duration_ms,
                success=True,
            )
            if row is not None:
                await session.commit()


def _parse_sse_for_toolcall(
    buffer: str,
    chunk: bytes,
) -> tuple[str, tuple[str, str] | None]:
    """Extract a ``tools/call`` request's tool name + id from SSE frames.

    Best-effort: returns the first observed tool-call frame. Usage recording is
    non-critical (the stream is already forwarded regardless).
    """
    buffer += chunk.decode(errors="ignore")
    lines = buffer.splitlines(keepends=True)
    buffer = lines.pop() if lines and not lines[-1].endswith(("\n", "\r")) else ""
    parsed: tuple[str, str] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("data:"):
            continue
        raw = stripped.removeprefix("data:").strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        found = _extract_toolcall(payload)
        if found is not None and parsed is None:
            parsed = found
    return buffer, parsed


def _extract_toolcall(payload: Any) -> tuple[str, str] | None:
    if not isinstance(payload, dict):
        return None
    method = payload.get("method")
    if method != "tools/call":
        return None
    params = payload.get("params") or {}
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str):
        return None
    rid = payload.get("id")
    rid_str = str(rid) if rid is not None else "unknown"
    return name, rid_str


async def _maybe_record_jsonrpc_usage(
    session: AsyncSession,
    creator_id: uuid.UUID,
    config_id: uuid.UUID,
    request_body: bytes,
    response_body: bytes,
) -> None:
    """Record one usage row for a ``tools/call`` JSON-RPC round-trip."""
    started = time.monotonic()
    extracted = _extract_toolcall(_safe_json(request_body))
    if extracted is None:
        return
    tool_name, _ = extracted
    success = _jsonrpc_response_success(_safe_json(response_body))
    duration_ms = int((time.monotonic() - started) * 1000)
    row = await McpUsageService(session).record_usage(
        creator_id=creator_id,
        mcp_server_config_id=config_id,
        tool_name=tool_name,
        duration_ms=duration_ms,
        success=success,
    )
    if row is not None:
        await session.commit()


def _safe_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None


def _jsonrpc_response_success(resp: Any) -> bool:
    if not isinstance(resp, dict):
        return False
    return "error" not in resp
