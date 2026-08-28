"""E2E smoke test: the running app reports healthy.

Run: uv run pytest tests/e2e -q
Requires the app to be up (docker compose up).
"""

from __future__ import annotations

import os

import httpx

BASE_URL = os.environ.get("OHE_BASE_URL", "http://localhost:8000")


async def test_app_healthy() -> None:
    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        resp = await ac.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
