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
        "resource_type": "users",
        "selector_kind": "all",
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
        assert body["resource_type"] == "users"
        assert body["selector_kind"] == "all"
        assert uuid.UUID(body["id"])

    async def test_create_with_attributes(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post(
            "/permissions",
            json=_payload(uid, attributes=["email", "name"]),
        )
        assert resp.status_code == 201
        assert resp.json()["attributes"] == ["email", "name"]

    async def test_create_by_id_selector(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post(
            "/permissions",
            json=_payload(uid, selector_kind="by_id", selector_value="abc"),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["selector_kind"] == "by_id"
        assert body["selector_value"] == "abc"

    async def test_create_custom_action(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post(
            "/permissions",
            json=_payload(
                uid,
                action="use",
                custom_action="deploy",
                resource_type="sandboxes",
            ),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["action"] == "use"
        assert body["custom_action"] == "deploy"

    async def test_create_invalid_action_returns_422(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        resp = await client.post("/permissions", json=_payload(uid, action="bogus"))
        assert resp.status_code == 422

    async def test_create_missing_user_id_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post("/permissions", json={"action": "read", "resource_type": "users"})
        assert resp.status_code == 422


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
    async def test_list_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/permissions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None

    async def test_list_filtered_by_user(self, client: AsyncClient) -> None:
        uid1 = await _make_user(client, email="u1@example.com")
        uid2 = await _make_user(client, email="u2@example.com")
        await client.post("/permissions", json=_payload(uid1, resource_type="users"))
        await client.post("/permissions", json=_payload(uid1, resource_type="sandboxes"))
        await client.post("/permissions", json=_payload(uid2, resource_type="users"))
        resp = await client.get(f"/permissions?user_id={uid1}")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert all(i["user_id"] == uid1 for i in body["items"])

    async def test_list_pagination(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        for rt in ["a", "b", "c", "d", "e"]:
            await client.post("/permissions", json=_payload(uid, resource_type=rt))
        resp = await client.get("/permissions?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None

    async def test_list_invalid_user_id_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/permissions?user_id=not-a-uuid")
        assert resp.status_code == 422


class TestUpdatePermissionRoute:
    async def test_update_action(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        pid = create.json()["id"]
        resp = await client.patch(f"/permissions/{pid}", json={"action": "write"})
        assert resp.status_code == 200
        assert resp.json()["action"] == "write"

    async def test_update_attributes(self, client: AsyncClient) -> None:
        uid = await _make_user(client)
        create = await client.post("/permissions", json=_payload(uid))
        pid = create.json()["id"]
        resp = await client.patch(f"/permissions/{pid}", json={"attributes": ["email"]})
        assert resp.status_code == 200
        assert resp.json()["attributes"] == ["email"]

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/permissions/{uuid.uuid4()}", json={"action": "write"})
        assert resp.status_code == 404


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
        resp = await client.get(f"/permissions?user_id={uid}")
        assert len(resp.json()["items"]) == 1
        await client.delete(f"/users/{uid}")
        resp = await client.get(f"/permissions?user_id={uid}")
        assert resp.status_code == 200
        assert resp.json()["items"] == []
