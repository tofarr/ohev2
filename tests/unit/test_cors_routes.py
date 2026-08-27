"""Route tests for the global CORS allow-list feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient


class TestCorsOriginCrud:
    async def test_create_and_list(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/cors-origins",
            json={"origin": "https://app.example.com"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["origin"] == "https://app.example.com"
        assert "id" in body
        assert "created_at" in body

        got = await client.get("/cors-origins")
        assert got.status_code == 200
        items = got.json()["items"]
        assert any(i["origin"] == "https://app.example.com" for i in items)

    async def test_create_duplicate_returns_409(self, client: AsyncClient) -> None:
        payload = {"origin": "https://dup.example.com"}
        first = await client.post("/cors-origins", json=payload)
        assert first.status_code == 201
        second = await client.post("/cors-origins", json=payload)
        assert second.status_code == 409

    async def test_list_pagination(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post(
                "/cors-origins",
                json={"origin": f"https://h{i}.example.com"},
            )
        page = await client.get("/cors-origins", params={"limit": 2})
        assert page.status_code == 200
        body = page.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_delete(self, client: AsyncClient) -> None:
        create = await client.post(
            "/cors-origins",
            json={"origin": "https://del.example.com"},
        )
        oid = create.json()["id"]
        resp = await client.delete(f"/cors-origins/{oid}")
        assert resp.status_code == 204
        assert (await client.get("/cors-origins")).json()["items"] == [] or all(
            i["id"] != oid for i in (await client.get("/cors-origins")).json()["items"]
        )

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/cors-origins/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestCorsMiddleware:
    async def test_allowed_origin_gets_cors_headers(self, client: AsyncClient) -> None:
        await client.post(
            "/cors-origins",
            json={"origin": "https://allowed.example.com"},
        )
        resp = await client.get(
            "/health",
            headers={"Origin": "https://allowed.example.com"},
        )
        assert resp.headers.get("access-control-allow-origin") == "https://allowed.example.com"
        assert resp.headers.get("access-control-allow-credentials") == "true"

    async def test_disallowed_origin_gets_no_cors_headers(self, client: AsyncClient) -> None:
        # Empty allow-list: no origin is permitted.
        resp = await client.get(
            "/health",
            headers={"Origin": "https://evil.example.com"},
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_request_without_origin_unaffected(self, client: AsyncClient) -> None:
        await client.post(
            "/cors-origins",
            json={"origin": "https://allowed.example.com"},
        )
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "access-control-allow-origin" not in resp.headers

    async def test_preflight_options_for_allowed_origin(self, client: AsyncClient) -> None:
        await client.post(
            "/cors-origins",
            json={"origin": "https://preflight.example.com"},
        )
        resp = await client.options(
            "/health",
            headers={
                "Origin": "https://preflight.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 204
        assert resp.headers.get("access-control-allow-origin") == "https://preflight.example.com"
        assert "access-control-allow-methods" in resp.headers
        assert "access-control-allow-headers" in resp.headers
        assert "access-control-max-age" in resp.headers

    async def test_preflight_for_disallowed_origin_no_headers(self, client: AsyncClient) -> None:
        resp = await client.options(
            "/health",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in resp.headers

    async def test_delete_invalidates_cache(self, client: AsyncClient) -> None:
        create = await client.post(
            "/cors-origins",
            json={"origin": "https://cached.example.com"},
        )
        oid = create.json()["id"]
        # Warm cache + assert allowed.
        resp = await client.get(
            "/health",
            headers={"Origin": "https://cached.example.com"},
        )
        assert resp.headers.get("access-control-allow-origin") == "https://cached.example.com"
        await client.delete(f"/cors-origins/{oid}")
        # Cache invalidated by delete; origin no longer permitted.
        resp2 = await client.get(
            "/health",
            headers={"Origin": "https://cached.example.com"},
        )
        assert "access-control-allow-origin" not in resp2.headers
