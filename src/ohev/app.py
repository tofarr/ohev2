"""Minimal FastAPI application entrypoint.

Routes are intentionally stubs at this stage; the REST consistency rules in
AGENTS.md §3 must be applied as resources are added.
"""

from __future__ import annotations

from fastapi import FastAPI

from ohev import __version__
from ohev.auth.auth_router import router as auth_router
from ohev.permission.permission_router import router as permission_router
from ohev.user.user_router import router as user_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="ohev",
        version=__version__,
        description="OpenHands Enterprise v2",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(user_router)
    app.include_router(permission_router)
    return app


app = create_app()
