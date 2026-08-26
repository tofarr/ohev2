"""Route tests for the permission feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient


async def _make_user(client: AsyncClient, email: str = "perm-route@example.com") -> str:
    resp = await client.post("/users", json={"email": email})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _payload(user_id: str, **overrides) -> dict:
    base = {
        "user_id": user_id,
        "action": "read",
        "resource_type": "user",
    }
    base.update(overrides)
    return base


class TestCreatePermissionRoute:
    async def test_create_permission(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post("/permissions", json=_payload(uid))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["action"] == "read"
        assert body["resource_type"] == "user"
        assert uuid.UUID(body["id"])

    async def test_create_with_attributes(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post(
            "/permissions",
            json=_payload(uid, attributes=["email", "name"]),
        )
        assert resp.status_code == 201
        assert resp.json()["attributes"] == ["email", "name"]

    async def test_create_permission_type(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post(
            "/permissions",
            json=_payload(uid, resource_type="permission"),
        )
        assert resp.status_code == 201
        assert resp.json()["resource_type"] == "permission"

    async def test_create_all_action(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post("/permissions", json=_payload(uid, action="all"))
        assert resp.status_code == 201
        assert resp.json()["action"] == "all"

    async def test_create_invalid_action_returns_422(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post("/permissions", json=_payload(uid, action="bogus"))
        assert resp.status_code == 422

    async def test_create_without_user_id_succeeds(self, client: AsyncClient) -> None:
        # user_id is optional (nullable) to support anonymous permissions.
        resp = await client.post("/permissions", json={"action": "read", "resource_type": "user"})
        assert resp.status_code == 201
        assert resp.json()["user_id"] is None


class TestGetPermissionRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        pid = create.json()["id"]
        resp = await client.get(f"/permissions/{pid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == pid

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/permissions/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestListPermissionsRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/permissions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None

    async def test_search_filtered_by_user(self, client: AsyncClient) -> None:
        uid1 = await _make_user(client, email="u1@example.com")
        uid2 = await _make_user(client, email="u2@example.com")
        await client.post("/permissions", json=_payload(uid1, resource_type="user"))
        await client.post("/permissions", json=_payload(uid1, resource_type="permission"))
        await client.post("/permissions", json=_payload(uid2, resource_type="user"))
        resp = await client.get(f"/permissions?user_id__eq={uid1}")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert all(i["user_id"] == uid1 for i in body["items"])

    async def test_search_pagination(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        for act in ["create", "read", "update", "delete", "search"]:
            await client.post("/permissions", json=_payload(uid, action=act))
        resp = await client.get("/permissions?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_search_invalid_user_id_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/permissions?user_id__eq=not-a-uuid")
        assert resp.status_code == 422


class TestCountPermissionsRoute:
    async def test_count_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/permissions/count")
        assert resp.status_code == 200
        assert resp.json() == {"count": 0}

    async def test_count_after_creates(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        for act in ["create", "read", "update"]:
            await client.post("/permissions", json=_payload(uid, action=act))
        resp = await client.get("/permissions/count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 3

    async def test_count_with_user_filter(self, client: AsyncClient) -> None:
        uid1 = await _make_user(client, email="u1@example.com")
        uid2 = await _make_user(client, email="u2@example.com")
        await client.post("/permissions", json=_payload(uid1))
        await client.post("/permissions", json=_payload(uid2))
        resp = await client.get(f"/permissions/count?user_id__eq={uid1}")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    async def test_count_excludes_deleted(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        await client.post("/permissions", json=_payload(uid, action="read"))
        await client.delete(f"/permissions/{create.json()['id']}")
        resp = await client.get("/permissions/count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1


class TestDeletePermissionRoute:
    async def test_delete_permission(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        pid = create.json()["id"]
        resp = await client.delete(f"/permissions/{pid}")
        assert resp.status_code == 204
        get_resp = await client.get(f"/permissions/{pid}")
        assert get_resp.status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/permissions/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestCascadeViaRoutes:
    async def test_deleting_user_removes_permissions(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        await client.post("/permissions", json=_payload(uid))
        resp = await client.get(f"/permissions?user_id__eq={uid}")
        assert len(resp.json()["items"]) == 1
        await client.delete(f"/users/{uid}")
        resp = await client.get(f"/permissions?user_id__eq={uid}")
        assert resp.status_code == 200
        assert resp.json()["items"] == []


class TestPermissionEnforcement:
    """Tests for the permission check on protected endpoints."""

    async def test_missing_auth_header_anonymous_allowed(self, app) -> None:
        # Auth is optional; without X-User-Id the request is treated as
        # anonymous and the baseline permissions grant access (200).
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/users")
        assert resp.status_code == 200

    async def test_invalid_auth_header_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/users", headers={"X-User-Id": "not-a-uuid"})
        assert resp.status_code == 401

    async def test_no_patch_endpoint_on_permissions(self, client: AsyncClient) -> None:
        """Permissions are immutable — PATCH must not exist (404 or 405)."""
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        pid = create.json()["id"]
        resp = await client.patch(f"/permissions/{pid}", json={"action": "update"})
        assert resp.status_code in (404, 405)
