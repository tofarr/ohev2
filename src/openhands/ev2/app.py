"""Minimal FastAPI application entrypoint.

Routes are intentionally stubs at this stage; the REST consistency rules in
AGENTS.md §3 must be applied as resources are added.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from openhands.ev2 import __version__
from openhands.ev2.api_key.api_key_router import router as api_key_router
from openhands.ev2.auth.auth_router import router as auth_router
from openhands.ev2.config import get_config
from openhands.ev2.cors.cors_middleware import CorsMiddleware
from openhands.ev2.cors.cors_router import router as cors_router
from openhands.ev2.db import get_session_factory
from openhands.ev2.role.role_router import router as role_router
from openhands.ev2.role.user_role_router import router as user_role_router
from openhands.ev2.user.user_router import router as user_router

# Sentinel IdP URL that selects the built-in dev identity provider
# (auth.dev_router). When idp.url == this value the dev IdP router is mounted so
# the system works out of the box without configuring an external IdP.
_DEV_IDP_URL = "/auth/dev"

logger = logging.getLogger(__name__)


async def _cleanup_loop() -> None:
    """Background sweep that deletes expired IdP refresh tokens.

    Runs every ``cleanup_interval`` seconds. A failure in one sweep is logged
    and the loop continues; the loop is cancelled on shutdown. When
    ``cleanup_interval`` is 0 the loop is not started and cleanup must be
    driven by an external scheduler (cron) — see README 'Cleanup processes'.
    """
    from openhands.ev2.auth.auth_service import AuthService

    cfg = get_config()
    interval = cfg.cleanup_interval
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        try:
            factory = get_session_factory()
            async with factory() as session:
                service = AuthService(session)
                try:
                    deleted = await service.delete_expired_tokens()
                finally:
                    await service.aclose()
            if deleted:
                logger.info("auth cleanup deleted %d expired IdP refresh tokens", deleted)
        except Exception:
            logger.exception("auth cleanup sweep failed; will retry next interval")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage the background cleanup task across the app lifetime."""
    task = asyncio.create_task(_cleanup_loop(), name="auth-cleanup")
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def create_app() -> FastAPI:
    app = FastAPI(
        title="OpenHands Enterprise",
        version=__version__,
        description="OpenHands Enterprise v2",
        lifespan=lifespan,
    )

    # Global, DB-backed CORS allow-list. Reads the cached allowed-origin set on
    # each cross-origin request; the list is managed via /cors-origins.
    app.add_middleware(CorsMiddleware)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(api_key_router)
    app.include_router(cors_router)
    app.include_router(role_router)
    app.include_router(user_role_router)
    app.include_router(user_router)
    # Mount the built-in dev identity provider when the configured IdP URL is the
    # dev sentinel. Read the env var directly (rather than get_config()) so app
    # construction does not require the full AppConfig env to be present at
    # import time; the dev router handlers resolve the full config per request.
    if os.environ.get("OHE_IDP_URL", _DEV_IDP_URL) == _DEV_IDP_URL:
        from openhands.ev2.auth.dev_router import router as dev_router

        app.include_router(dev_router)
    return app


app = create_app()
