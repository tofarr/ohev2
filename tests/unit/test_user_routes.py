"""Route tests for the user feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient


class TestCreateUserRoute:
    async def test_create_user(self, client: AsyncClient) -> None:
        resp = await client.post("/users", json={"email": "alice@example.com"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "alice@example.com"
        assert uuid.UUID(body["id"])
        assert body["created_at"] is not None

    async def test_create_duplicate_email_returns_409(self, client: AsyncClient) -> None:
        payload = {"email": "dup@example.com"}
        resp = await client.post("/users", json=payload)
        assert resp.status_code == 201
        resp2 = await client.post("/users", json=payload)
        assert resp2.status_code == 409

    async def test_create_invalid_email_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post("/users", json={"email": "not-an-email"})
        assert resp.status_code == 422


class TestGetUserRoute:
    async def test_get_existing_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "bob@example.com"})
        uid = create.json()["id"]
        resp = await client.get(f"/users/{uid}")
        assert resp.status_code == 200
        assert resp.json()["email"] == "bob@example.com"

    async def test_get_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/users/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users/not-a-uuid")
        assert resp.status_code == 422


class TestListUsersRoute:
    async def test_list_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/users")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_list_with_limit(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/users", json={"email": f"u{i}@example.com"})
        resp = await client.get("/users?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        assert body["limit"] == 2

    async def test_list_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/users", json={"email": f"p{i}@example.com"})
        resp1 = await client.get("/users?limit=2")
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/users?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_list_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/users?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_list_limit_out_of_range_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/users?limit=0")
        assert resp.status_code == 422
        resp = await client.get("/users?limit=101")
        assert resp.status_code == 422


class TestUpdateUserRoute:
    async def test_update_email(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "old@example.com"})
        uid = create.json()["id"]
        resp = await client.patch(f"/users/{uid}", json={"email": "new@example.com"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "new@example.com"

    async def test_update_no_fields(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "keep@example.com"})
        uid = create.json()["id"]
        resp = await client.patch(f"/users/{uid}", json={})
        assert resp.status_code == 200
        assert resp.json()["email"] == "keep@example.com"

    async def test_update_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/users/{uuid.uuid4()}", json={"email": "x@example.com"})
        assert resp.status_code == 404


class TestDeleteUserRoute:
    async def test_delete_user(self, client: AsyncClient) -> None:
        create = await client.post("/users", json={"email": "del@example.com"})
        uid = create.json()["id"]
        resp = await client.delete(f"/users/{uid}")
        assert resp.status_code == 204
        get_resp = await client.get(f"/users/{uid}")
        assert get_resp.status_code == 404

    async def test_delete_missing_user_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/users/{uuid.uuid4()}")
        assert resp.status_code == 404
