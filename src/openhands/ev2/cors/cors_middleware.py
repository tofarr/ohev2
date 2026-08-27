"""ASGI middleware that enforces the global, DB-backed CORS allow-list.

Unlike Starlette's `CORSMiddleware`, the allow-list is not fixed at startup —
it lives in the ``allowed_origins`` table and is mutable at runtime via
``/cors-origins``. This middleware reads the cached set
(``get_allowed_origins_cached``) on each request carrying an ``Origin``
header. An origin in the set gets ``Access-Control-Allow-Origin`` set to that
exact origin (never ``*``), ``Access-Control-Allow-Credentials: true``, and the
preflight-requested method/headers echoed. An origin not in the set gets no
CORS headers, so the browser blocks the cross-origin read.

This is **CORS access control** (which cross-origin JavaScript may read
responses), not an XSRF defense for cookies — that is handled by the
SameSite=strict session cookie.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from openhands.ev2.cors.cors_service import get_allowed_origins_cached

# Default allowed request headers mirrored from Starlette's CORSMiddleware.
_DEFAULT_ALLOWED_HEADERS: tuple[str, ...] = (
    "accept",
    "authorization",
    "content-disposition",
    "content-type",
    "content-length",
    "origin",
    "range",
    "user-agent",
    "x-requested-with",
)


class GlobalCorsMiddleware:
    """Enforce the DB-backed global CORS allow-list on every request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allow_methods: tuple[str, ...] = ("GET", "POST", "PATCH", "DELETE", "OPTIONS"),
        allow_headers: tuple[str, ...] = _DEFAULT_ALLOWED_HEADERS,
        max_age: int = 600,
    ) -> None:
        self.app = app
        self.allow_methods = {m.upper() for m in allow_methods}
        self.allow_headers = {h.lower() for h in allow_headers}
        self.max_age = max_age

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        origin = request.headers.get("origin")
        if origin is None:
            await self.app(scope, receive, send)
            return

        allowed = await get_allowed_origins_cached()
        if origin not in allowed:
            # Not a permitted origin: do not add CORS headers; the browser
            # will block the cross-origin response.
            await self.app(scope, receive, send)
            return

        if request.method == "OPTIONS" and "access-control-request-method" in request.headers:
            await self._preflight(scope, receive, send, origin)
            return

        await self._simple(scope, receive, send, origin)

    async def _preflight(self, scope: Scope, receive: Receive, send: Send, origin: str) -> None:
        headers: list[tuple[str, str]] = [
            ("access-control-allow-origin", origin),
            ("access-control-allow-credentials", "true"),
            ("access-control-allow-methods", ", ".join(sorted(self.allow_methods))),
            ("access-control-allow-headers", ", ".join(sorted(self.allow_headers))),
            ("access-control-max-age", str(self.max_age)),
            ("vary", "origin"),
        ]

        response = Response(status_code=204, headers=dict(headers))
        await response(scope, receive, send)

    async def _simple(self, scope: Scope, receive: Receive, send: Send, origin: str) -> None:
        acao = b"access-control-allow-origin"
        acac = b"access-control-allow-credentials"
        vary = b"vary"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw = message.get("headers", [])
                existing = {k.lower() for k, _ in raw}
                out = list(raw)
                if acao not in existing:
                    out.append((acao, origin.encode()))
                if acac not in existing:
                    out.append((acac, b"true"))
                if vary not in existing:
                    out.append((vary, b"origin"))
                message["headers"] = out
            await send(message)

        await self.app(scope, receive, send_wrapper)
