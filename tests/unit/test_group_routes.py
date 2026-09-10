"""Route tests for the group feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient


class TestGroupCreateRoute:
    async def test_create_group(self, client: AsyncClient) -> None:
        resp = await client.post("/groups", json={"name": "team-a", "description": "desc"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "team-a"
        assert body["description"] == "desc"
        assert "id" in body
        assert "creator_id" in body
        assert "created_at" in body
        assert "updated_at" in body

    async def test_create_group_without_description(self, client: AsyncClient) -> None:
        resp = await client.post("/groups", json={"name": "team-b"})
        assert resp.status_code == 201
        assert resp.json()["description"] is None


class TestGroupGetRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "g"})).json()["id"]
        resp = await client.get(f"/groups/{gid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == gid

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/groups/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestGroupSearchRoute:
    async def test_search_returns_groups(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/groups", json={"name": f"team-{i}"})
        resp = await client.get("/groups")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) >= 3
        assert body["limit"] == 50

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/groups", json={"name": f"page-{i}"})
        resp1 = await client.get("/groups?limit=2")
        assert len(resp1.json()["items"]) == 2
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/groups?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/groups?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_name_filter(self, client: AsyncClient) -> None:
        await client.post("/groups", json={"name": "alpha"})
        await client.post("/groups", json={"name": "beta"})
        resp = await client.get("/groups?name__contains=alp")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all("alp" in i["name"] for i in items)


class TestGroupCountRoute:
    async def test_count_after_create(self, client: AsyncClient) -> None:
        await client.post("/groups", json={"name": "c1"})
        await client.post("/groups", json={"name": "c2"})
        resp = await client.get("/groups/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 2


class TestGroupUpdateRoute:
    async def test_update_name_and_description(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "old"})).json()["id"]
        resp = await client.patch(f"/groups/{gid}", json={"name": "new", "description": "updated"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "new"
        assert body["description"] == "updated"

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/groups/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404


class TestGroupDeleteRoute:
    async def test_delete_group(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "del"})).json()["id"]
        resp = await client.delete(f"/groups/{gid}")
        assert resp.status_code == 204
        assert (await client.get(f"/groups/{gid}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/groups/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestGroupBatchRoute:
    async def test_batch_read_aligned_with_nulls(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "b"})).json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/groups/batch?ids={gid}&ids={missing}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == gid
        assert items[1] is None

    async def test_batch_empty_ids(self, client: AsyncClient) -> None:
        resp = await client.get("/groups/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_write_create_update_delete(self, client: AsyncClient) -> None:
        # Create two groups, update one, delete the other in a single batch.
        g1 = (await client.post("/groups", json={"name": "bw1"})).json()["id"]
        g2 = (await client.post("/groups", json={"name": "bw2"})).json()["id"]
        resp = await client.post(
            "/groups/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"name": "bw3"}},
                    {"op": "update", "id": g1, "data": {"name": "bw1-updated"}},
                    {"op": "delete", "id": g2},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["name"] == "bw3"
        assert items[1]["name"] == "bw1-updated"
        assert items[2] is None


class TestGroupUserCreateRoute:
    async def test_create_membership(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "m"})).json()["id"]
        uid = (
            await client.post("/users", json={"email": "m@example.com", "username": "m"})
        ).json()["id"]
        resp = await client.post("/group-users", json={"group_id": gid, "user_id": uid})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["group_id"] == gid
        assert body["user_id"] == uid
        assert "creator_id" in body
        assert "created_at" in body

    async def test_create_duplicate_returns_409(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "dup"})).json()["id"]
        uid = (
            await client.post("/users", json={"email": "dup@example.com", "username": "dup"})
        ).json()["id"]
        first = await client.post("/group-users", json={"group_id": gid, "user_id": uid})
        assert first.status_code == 201
        second = await client.post("/group-users", json={"group_id": gid, "user_id": uid})
        assert second.status_code == 409

    async def test_create_missing_group_returns_404(self, client: AsyncClient) -> None:
        uid = (
            await client.post("/users", json={"email": "mg@example.com", "username": "mg"})
        ).json()["id"]
        resp = await client.post(
            "/group-users", json={"group_id": str(uuid.uuid4()), "user_id": uid}
        )
        assert resp.status_code == 404

    async def test_create_missing_user_returns_404(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "mu"})).json()["id"]
        resp = await client.post(
            "/group-users", json={"group_id": gid, "user_id": str(uuid.uuid4())}
        )
        assert resp.status_code == 404


class TestGroupUserGetRoute:
    async def test_get_existing(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "gg"})).json()["id"]
        uid = (
            await client.post("/users", json={"email": "gg@example.com", "username": "gg"})
        ).json()["id"]
        lid = (await client.post("/group-users", json={"group_id": gid, "user_id": uid})).json()[
            "id"
        ]
        resp = await client.get(f"/group-users/{lid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == lid

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/group-users/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestGroupUserSearchRoute:
    async def test_search_group_filter(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "sf"})).json()["id"]
        for i in range(3):
            uid = (
                await client.post(
                    "/users", json={"email": f"s{i}@example.com", "username": f"s{i}"}
                )
            ).json()["id"]
            await client.post("/group-users", json={"group_id": gid, "user_id": uid})
        resp = await client.get(f"/group-users?group_id__eq={gid}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        assert all(i["group_id"] == gid for i in items)


class TestGroupUserDeleteRoute:
    async def test_delete_membership(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "dm"})).json()["id"]
        uid = (
            await client.post("/users", json={"email": "dm@example.com", "username": "dm"})
        ).json()["id"]
        lid = (await client.post("/group-users", json={"group_id": gid, "user_id": uid})).json()[
            "id"
        ]
        resp = await client.delete(f"/group-users/{lid}")
        assert resp.status_code == 204
        assert (await client.get(f"/group-users/{lid}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/group-users/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestGroupUserBatchRoute:
    async def test_batch_read_aligned(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "br"})).json()["id"]
        uid = (
            await client.post("/users", json={"email": "br@example.com", "username": "br"})
        ).json()["id"]
        lid = (await client.post("/group-users", json={"group_id": gid, "user_id": uid})).json()[
            "id"
        ]
        resp = await client.get(f"/group-users/batch?ids={lid}&ids={uuid.uuid4()}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == lid
        assert items[1] is None

    async def test_batch_write_create_delete(self, client: AsyncClient) -> None:
        gid = (await client.post("/groups", json={"name": "bwc"})).json()["id"]
        u1 = (
            await client.post("/users", json={"email": "bwc1@example.com", "username": "bwc1"})
        ).json()["id"]
        u2 = (
            await client.post("/users", json={"email": "bwc2@example.com", "username": "bwc2"})
        ).json()["id"]
        existing = await client.post("/group-users", json={"group_id": gid, "user_id": u1})
        existing_id = existing.json()["id"]
        resp = await client.post(
            "/group-users/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"group_id": gid, "user_id": u2}},
                    {"op": "delete", "id": existing_id},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["user_id"] == u2
        assert items[1] is None
