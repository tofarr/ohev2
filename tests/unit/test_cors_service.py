"""Service tests for the global CORS allow-list feature.

The cache layer is also exercised directly: creation/deletion invalidate the
in-memory set so the middleware sees updates without waiting for the TTL.
"""

from __future__ import annotations

import uuid

import pytest

from openhands.ev2.cors.cors_service import (
    AllowedOriginConflictError,
    AllowedOriginNotFoundError,
    CorsService,
    get_allowed_origins_cached,
    reset_cors_cache,
)


@pytest.fixture
def service(session) -> CorsService:
    return CorsService(session)


class TestCorsService:
    async def test_create_and_list(self, service: CorsService) -> None:
        row = await service.create_allowed_origin("https://a.example.com")
        assert row.origin == "https://a.example.com"
        origins, _ = await service.list_allowed_origins(limit=10)
        assert {o.origin for o in origins} == {"https://a.example.com"}

    async def test_create_duplicate_raises(self, service: CorsService) -> None:
        await service.create_allowed_origin("https://dup.example.com")
        await service._session.commit()
        with pytest.raises(AllowedOriginConflictError):
            await service.create_allowed_origin("https://dup.example.com")

    async def test_list_pagination(self, service: CorsService) -> None:
        for i in range(3):
            await service.create_allowed_origin(f"https://h{i}.example.com")
        page, next_cursor = await service.list_allowed_origins(limit=2)
        assert len(page) == 2
        assert next_cursor is not None
        page2, next_cursor2 = await service.list_allowed_origins(cursor=next_cursor, limit=2)
        assert len(page2) == 1
        assert next_cursor2 is None

    async def test_delete(self, service: CorsService) -> None:
        row = await service.create_allowed_origin("https://del.example.com")
        await service.delete_allowed_origin(row.id)
        origins, _ = await service.list_allowed_origins(limit=10)
        assert origins == []

    async def test_delete_missing_raises(self, service: CorsService) -> None:
        with pytest.raises(AllowedOriginNotFoundError):
            await service.delete_allowed_origin(uuid.uuid4())


class TestCorsCache:
    async def test_cache_reflects_creates_and_deletes(self, service: CorsService) -> None:
        reset_cors_cache()
        assert await get_allowed_origins_cached() == set()
        row = await service.create_allowed_origin("https://cached.example.com")
        await service._session.commit()
        # create_allowed_origin invalidates the cache.
        assert await get_allowed_origins_cached() == {"https://cached.example.com"}
        await service.delete_allowed_origin(row.id)
        await service._session.commit()
        # delete_allowed_origin invalidates the cache.
        assert await get_allowed_origins_cached() == set()
        reset_cors_cache()

    async def test_cache_returns_copy(self, service: CorsService) -> None:
        reset_cors_cache()
        await service.create_allowed_origin("https://copy.example.com")
        await service._session.commit()
        first = await get_allowed_origins_cached()
        first.add("https://evil.example.com")
        second = await get_allowed_origins_cached()
        assert "https://evil.example.com" not in second
        reset_cors_cache()
