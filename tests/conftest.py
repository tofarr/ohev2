"""Shared pytest fixtures.

Uses an embedded PostgreSQL server (pytest-postgresql) so unit tests are hermetic.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ohev.app import create_app


@pytest.fixture
async def client() -> AsyncClient:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
