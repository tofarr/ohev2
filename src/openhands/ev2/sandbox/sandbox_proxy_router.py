"""Reverse proxy to the agent server running inside a live sandbox.

A single wildcard surface mounted under ``/sandbox-proxy/{sandbox_id}/*`` that
authenticates the caller through the standard auth dependencies, authorizes
``Action.USE`` on the governed ``SandboxConfig``, then forwards the raw HTTP
request (or WebSocket upgrade) to the sandbox's internal agent server with the
sandbox's decrypted ``session_api_key`` injected as ``X-Session-API-Key``. The
caller never receives the session key or the internal port — it authenticates
with its own user-scoped credential and the proxy re-authenticates upstream.

The proxy resolves the upstream URL itself from ``sandbox.exposed_urls`` (the
entry whose ``name == "agent_server"``), keeping it backend-agnostic. SSE
responses are streamed byte-for-byte; non-SSE responses are returned with
status, content-type, and body intact. Hop-by-hop headers are stripped per the
MCP proxy convention.

This mirrors :mod:`openhands.ev2.mcp_server_config.mcp_proxy_router` — a
transport-layer forwarder with no business logic in the handlers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Annotated, cast
from urllib.parse import urlparse

import httpx
import websockets
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import StreamingResponse
from websockets.asyncio.client import ClientConnection

from openhands.ev2.auth.auth_dependencies import (
    depends_permissions,
    resolve_permission_filter,
)
from openhands.ev2.auth.auth_tokens import InvalidTokenError, TokenService
from openhands.ev2.config import get_config
from openhands.ev2.db import get_session_factory
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxStatus
from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError, SandboxService
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import SearchFilter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox-proxy", tags=["sandbox-proxy"], include_in_schema=False)

# ``USE`` permission on the sandbox config — resolved once at import time.
_use_dep = depends_permissions(SandboxConfig, Action.USE)

_AGENT_SERVER_NAME = "agent_server"
_SESSION_KEY_HEADER = "X-Session-API-Key"

# Hop-by-hop headers (RFC 7230 §6.1) — never forwarded in either direction.
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

# Request headers that are specific to the client→proxy leg and must not be
# forwarded upstream (httpx recomputes content-length/host; the caller's auth
# credential and cookie are for this app, not the sandbox).
_STRIP_REQUEST_HEADERS = _HOP_BY_HOP | {
    "host",
    "content-length",
    "authorization",
    "cookie",
    "x-session-api-key",
}

_PROXY_METHODS = ["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS", "HEAD"]


async def _resolve_sandbox(
    request: Request | WebSocket,
    sandbox_id: str,
    perm_filter: SearchFilter[SandboxConfig],
) -> Sandbox:
    """Load the live sandbox, scoped by the caller's USE permission.

    Raises 404 when the sandbox does not exist or is out of scope, and 503 when
    it is not ``ACTIVE`` or has no ``agent_server`` exposed URL.
    """
    service = _get_sandbox_service(request)
    try:
        sandbox = await service.get_sandbox(
            sandbox_id, perm_filter=cast(SearchFilter[Sandbox], perm_filter)
        )
    except SandboxNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sandbox not found: {exc}",
        ) from exc
    if sandbox.status is not SandboxStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sandbox is not ready (status={sandbox.status.value}).",
        )
    if not sandbox.session_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox has no session API key.",
        )
    if not _agent_server_url(sandbox):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox has no agent_server exposed URL.",
        )
    return sandbox


def _get_sandbox_service(connection: Request | WebSocket) -> SandboxService:
    """Resolve the app-scoped sandbox service for an HTTP or WS connection."""
    service = getattr(connection.app.state, "sandbox_service", None)
    if not isinstance(service, SandboxService):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sandbox service is not available.",
        )
    return service


def _agent_server_url(sandbox: Sandbox) -> str | None:
    """Return the agent_server URL from ``exposed_urls`` (without trailing slash)."""
    for entry in sandbox.exposed_urls or []:
        if entry.name == _AGENT_SERVER_NAME:
            return entry.url.rstrip("/")
    return None


def _upstream_http_url(sandbox: Sandbox, path: str) -> str:
    base = _agent_server_url(sandbox)
    assert base is not None  # checked by _resolve_sandbox
    # Avoid a double slash when path is empty.
    return f"{base}/{path}" if path else base


def _upstream_ws_url(sandbox: Sandbox, path: str) -> str:
    base = _agent_server_url(sandbox)
    assert base is not None
    parsed = urlparse(base)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_base = f"{scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    return f"{ws_base}/{path}" if path else ws_base


def _forward_request_headers(request: Request) -> dict[str, str]:
    """Build the upstream request headers from the client's, stripping hop-by-hop
    and leg-specific headers. ``X-Session-API-Key`` is added by the caller.
    """
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in _STRIP_REQUEST_HEADERS:
            headers[name] = value
    return headers


def _passthrough_response_headers(upstream: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in upstream.headers.items():
        if name.lower() not in _HOP_BY_HOP and name.lower() != "x-session-api-key":
            out[name] = value
    return out


@router.api_route(
    "/{sandbox_id}/{path:path}",
    methods=_PROXY_METHODS,
    response_model=None,
)
async def proxy_http(
    sandbox_id: str,
    path: str,
    request: Request,
    perm_filter: Annotated[
        SearchFilter[SandboxConfig],
        Depends(_use_dep),
    ],
) -> Response | StreamingResponse:
    """Forward an HTTP request to the sandbox's internal agent server."""
    sandbox = await _resolve_sandbox(request, sandbox_id, perm_filter)
    upstream_url = _upstream_http_url(sandbox, path)
    body = await request.body()
    headers = _forward_request_headers(request)
    headers[_SESSION_KEY_HEADER] = sandbox.session_api_key or ""

    client = httpx.AsyncClient(timeout=None)
    upstream = await client.send(
        client.build_request(
            request.method,
            upstream_url,
            content=body,
            headers=headers,
            params=request.query_params,
        ),
        stream=True,
    )
    content_type = upstream.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        return StreamingResponse(
            _stream_passthrough(client, upstream),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_passthrough_response_headers(upstream),
        )
    content = await upstream.aread()
    await upstream.aclose()
    await client.aclose()
    return Response(
        content=content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
        headers=_passthrough_response_headers(upstream),
    )


@router.websocket("/{sandbox_id}/{path:path}")
async def proxy_websocket(
    sandbox_id: str,
    path: str,
    websocket: WebSocket,
) -> None:
    """Relay a WebSocket connection bidirectionally to the sandbox agent server.

    The sandbox's ``session_api_key`` is injected as ``X-Session-API-Key`` on
    the upstream handshake; the agent server authenticates the WebSocket via
    that header (no URL-param or first-message auth needed).

    Auth & permission are resolved manually rather than via
    ``Depends(depends_permissions)``: the standard ``depends_access_token``
    dependency uses FastAPI HTTP ``Security`` schemes (``APIKeyHeader`` /
    ``HTTPBearer``) which do not resolve for WebSocket scopes. The same
    ``TokenService.authenticate`` + ``resolve_permission_filter`` path is used
    so the authorization outcome is identical to the HTTP handler's.
    """
    # Auth/permission + sandbox resolution before accepting the client
    # WebSocket so failures surface as close codes rather than an
    # accepted-then-immediately-closed socket.
    try:
        perm_filter = await _resolve_ws_permission(websocket)
        sandbox = await _resolve_sandbox(websocket, sandbox_id, perm_filter)
    except HTTPException as exc:
        await websocket.close(code=_ws_close_code(exc.status_code), reason=str(exc.detail))
        return

    upstream_url = _upstream_ws_url(sandbox, path)
    session_key = sandbox.session_api_key or ""
    await websocket.accept()
    try:
        async with websockets.connect(
            upstream_url,
            additional_headers={_SESSION_KEY_HEADER: session_key},
            open_timeout=30,
        ) as upstream:
            await _relay(websocket, upstream)
    except websockets.exceptions.ConnectionClosed:
        pass
    except WebSocketDisconnect:
        pass


async def _resolve_ws_permission(websocket: WebSocket) -> SearchFilter[SandboxConfig]:
    """Authenticate the WebSocket caller and authorize ``USE`` on SandboxConfig.

    Mirrors ``Depends(depends_permissions(SandboxConfig, Action.USE))`` for the
    HTTP path, but reads the credential directly from the WebSocket headers /
    cookie because FastAPI's ``Security`` schemes do not run for WebSocket
    scopes. Closes the socket with 4401/4403 on failure.
    """
    token = _extract_ws_token(websocket)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: action=use resource=SandboxConfig",
        )
    factory = get_session_factory()
    async with factory() as session:
        try:
            resolved = await TokenService(session).authenticate(token)
        except InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired auth token.",
            ) from exc
        if not resolved.enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired auth token.",
            )
        # Reuse the same authorization reduction as the HTTP path. A WebSocket
        # has the ``.state``/``.cookies`` attributes the resolver caches on,
        # so it is passed directly (the ``Request`` annotation is structural).
        effective = await resolve_permission_filter(
            SandboxConfig, Action.USE, cast("Request", websocket), session, resolved
        )
        await session.rollback()
    if effective is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: action=use resource=SandboxConfig",
        )
    return cast(SearchFilter[SandboxConfig], effective)


def _extract_ws_token(websocket: WebSocket) -> str | None:
    """Read the bearer/api-key credential from the WebSocket handshake."""
    api_key = websocket.headers.get("x-api-key")
    if api_key:
        return api_key
    auth = websocket.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie_name = get_config().auth_cookie_name
    return websocket.cookies.get(cookie_name)


def _ws_close_code(http_status: int) -> int:
    """Map an HTTP status to a WebSocket close code for pre-accept failures."""
    if http_status == status.HTTP_404_NOT_FOUND:
        return 4404
    if http_status == status.HTTP_403_FORBIDDEN:
        return 4403
    if http_status == status.HTTP_401_UNAUTHORIZED:
        return 4401
    return 4500


async def _stream_passthrough(
    client: httpx.AsyncClient,
    upstream: httpx.Response,
) -> AsyncIterator[bytes]:
    try:
        async for chunk in upstream.aiter_bytes():
            yield chunk
    finally:
        await upstream.aclose()
        await client.aclose()


async def _relay(client: WebSocket, upstream: ClientConnection) -> None:
    """Relay text and binary frames bidirectionally until either side closes."""
    client_to_upstream = asyncio.create_task(_pump_client_to_upstream(client, upstream))
    upstream_to_client = asyncio.create_task(_pump_upstream_to_client(upstream, client))
    done, pending = await asyncio.wait(
        {client_to_upstream, upstream_to_client},
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()
    for task in done:
        # Surface unexpected exceptions to the logger; normal closures are silent.
        exc = task.exception()
        if exc is not None and not isinstance(
            exc, (WebSocketDisconnect, websockets.exceptions.ConnectionClosed)
        ):
            logger.debug("sandbox proxy websocket relay task error: %s", exc)


async def _pump_client_to_upstream(
    client: WebSocket,
    upstream: ClientConnection,
) -> None:
    while True:
        message = await client.receive()
        if message["type"] == "websocket.disconnect":
            return
        if message.get("text") is not None:
            await upstream.send(message["text"])
        elif message.get("bytes") is not None:
            await upstream.send(message["bytes"])


async def _pump_upstream_to_client(
    upstream: ClientConnection,
    client: WebSocket,
) -> None:
    async for message in upstream:
        if isinstance(message, str):
            await client.send_text(message)
        else:
            await client.send_bytes(message)
