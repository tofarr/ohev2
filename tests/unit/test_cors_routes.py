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


class TestBatchCorsOriginsRoute:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        a = await client.post("/cors-origins", json={"origin": "https://ba.example.com"})
        b = await client.post("/cors-origins", json={"origin": "https://bb.example.com"})
        aid, bid = a.json()["id"], b.json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/cors-origins/batch?ids={aid}&ids={missing}&ids={bid}")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == aid
        assert items[1] is None
        assert items[2]["id"] == bid

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/cors-origins/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_preserves_duplicate_ids(self, client: AsyncClient) -> None:
        a = await client.post("/cors-origins", json={"origin": "https://bdup.example.com"})
        aid = a.json()["id"]
        resp = await client.get(f"/cors-origins/batch?ids={aid}&ids={aid}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == aid
        assert items[1]["id"] == aid

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/cors-origins/batch?{ids}")
        assert resp.status_code == 422


class TestBatchWriteCorsOrigins:
    """POST /cors-origins/batch — mix of create/delete in one transaction (no update)."""

    async def test_batch_mix_create_delete_returns_positional_results(
        self, client: AsyncClient
    ) -> None:
        create = await client.post("/cors-origins", json={"origin": "https://bw1.example.com"})
        oid = create.json()["id"]
        resp = await client.post(
            "/cors-origins/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"origin": "https://bw2.example.com"}},
                    {"op": "delete", "id": oid},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["origin"] == "https://bw2.example.com"
        assert items[1] is None
        # The deleted origin no longer appears in the collection.
        origins = (await client.get("/cors-origins?limit=100")).json()["items"]
        assert all(o["id"] != oid for o in origins)

    async def test_batch_atomic_rollback_on_missing_delete(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/cors-origins/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"origin": "https://bwrb.example.com"}},
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        origins = (await client.get("/cors-origins?limit=100")).json()["items"]
        assert all(o["origin"] != "https://bwrb.example.com" for o in origins)

    async def test_batch_conflict_rolls_back_whole_batch(self, client: AsyncClient) -> None:
        await client.post("/cors-origins", json={"origin": "https://bwconflict.example.com"})
        resp = await client.post(
            "/cors-origins/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"origin": "https://bwfresh.example.com"}},
                    {"op": "create", "data": {"origin": "https://bwconflict.example.com"}},  # 409
                ]
            },
        )
        assert resp.status_code == 409
        origins = (await client.get("/cors-origins?limit=100")).json()["items"]
        assert all(o["origin"] != "https://bwfresh.example.com" for o in origins)

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/cors-origins/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_update_op_rejected(self, client: AsyncClient) -> None:
        # Origins are immutable; an update op is not a valid discriminator value.
        resp = await client.post(
            "/cors-origins/batch",
            json={"operations": [{"op": "update", "id": str(uuid.uuid4()), "data": {}}]},
        )
        assert resp.status_code == 422


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
