"""Route tests for the api_key feature (DB-backed, via ASGI client)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token

_TEST_USER_ID = uuid.UUID("12345678-1234-5678-1234-456789abcdef")


class TestCreateApiKeyRoute:
    async def test_create_api_key(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api-keys",
            json={"name": "ci-key"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["user_id"] == str(_TEST_USER_ID)
        assert body["name"] == "ci-key"
        assert body["enabled"] is True
        assert body["expires_at"] is None
        assert uuid.UUID(body["id"])
        assert body["key_prefix"]
        assert body["token"]
        # The opaque plaintext authenticates via X-API-Key for the user.
        auth = await client.get("/users", headers={"X-API-Key": body["token"]})
        assert auth.status_code == 200

    async def test_create_api_key_with_expiry(self, client: AsyncClient) -> None:
        expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        resp = await client.post(
            "/api-keys",
            json={"expires_at": expires},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["expires_at"] is not None

    async def test_create_api_key_disabled(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api-keys",
            json={"name": "off", "enabled": False},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["enabled"] is False
        # A disabled key does not authenticate.
        auth = await client.get("/users", headers={"X-API-Key": body["token"]})
        assert auth.status_code == 401

    async def test_create_api_key_empty_name_returns_422(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api-keys",
            json={"name": "  "},
        )
        assert resp.status_code == 422

    async def test_create_api_key_derives_user_id_from_principal(self, client: AsyncClient) -> None:
        # user_id is never accepted on the payload; it is derived from the
        # authenticated principal (the seeded test user).
        resp = await client.post("/api-keys", json={"name": "no-user"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["user_id"] == str(_TEST_USER_ID)

    async def test_create_api_key_ignores_payload_user_id(self, client: AsyncClient) -> None:
        # A client-supplied user_id must be ignored in favor of the principal.
        other = uuid.uuid4()
        resp = await client.post("/api-keys", json={"user_id": str(other), "name": "ignored"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["user_id"] == str(_TEST_USER_ID)


class TestGetApiKeyRoute:
    async def test_get_existing_api_key(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "g"})
        kid = create.json()["id"]
        resp = await client.get(f"/api-keys/{kid}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "g"

    async def test_get_missing_api_key_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/api-keys/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys/not-a-uuid")
        assert resp.status_code == 422


class TestSearchApiKeysRoute:
    async def test_search_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["next_cursor"] is None
        assert body["limit"] == 50

    async def test_search_with_limit(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/api-keys", json={"name": f"k{i}"})
        resp = await client.get("/api-keys?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        assert body["limit"] == 2

    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(4):
            await client.post("/api-keys", json={"name": f"p{i}"})
        resp1 = await client.get("/api-keys?limit=2")
        cursor = resp1.json()["next_cursor"]
        assert cursor is not None
        resp2 = await client.get(f"/api-keys?limit=2&cursor={cursor}")
        assert resp2.status_code == 200
        assert len(resp2.json()["items"]) == 2
        # A third page exhausts the 4 items.
        cursor2 = resp2.json()["next_cursor"]
        assert cursor2 is not None
        resp3 = await client.get(f"/api-keys?limit=2&cursor={cursor2}")
        assert resp3.status_code == 200
        assert resp3.json()["next_cursor"] is None

    async def test_search_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_search_limit_out_of_range_returns_422(self, client: AsyncClient) -> None:
        assert (await client.get("/api-keys?limit=0")).status_code == 422
        assert (await client.get("/api-keys?limit=101")).status_code == 422

    async def test_search_name_contains_filter(self, client: AsyncClient) -> None:
        await client.post("/api-keys", json={"name": "Admin"})
        await client.post("/api-keys", json={"name": "viewer"})
        resp = await client.get("/api-keys?name__contains=ADMIN")
        assert resp.status_code == 200
        names = {k["name"] for k in resp.json()["items"]}
        assert "Admin" in names
        assert "viewer" not in names

    async def test_search_user_id_eq_filter(self, client: AsyncClient) -> None:
        await client.post("/api-keys", json={"name": "mine"})
        resp = await client.get(f"/api-keys?user_id__eq={_TEST_USER_ID}")
        assert resp.status_code == 200
        for k in resp.json()["items"]:
            assert k["user_id"] == str(_TEST_USER_ID)

    async def test_search_enabled_eq_filter(self, client: AsyncClient) -> None:
        await client.post(
            "/api-keys",
            json={"name": "on", "enabled": True},
        )
        await client.post(
            "/api-keys",
            json={"name": "off", "enabled": False},
        )
        resp = await client.get("/api-keys?enabled__eq=false")
        assert resp.status_code == 200
        names = {k["name"] for k in resp.json()["items"]}
        assert names == {"off"}


class TestCountApiKeysRoute:
    async def test_count_empty(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys/count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    async def test_count_after_creates(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/api-keys", json={"name": f"c{i}"})
        resp = await client.get("/api-keys/count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 3

    async def test_count_with_name_filter(self, client: AsyncClient) -> None:
        await client.post("/api-keys", json={"name": "admin"})
        await client.post("/api-keys", json={"name": "viewer"})
        resp = await client.get("/api-keys/count?name__contains=admin")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1


class TestBatchReadApiKeysRoute:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        a = await client.post("/api-keys", json={"name": "a"})
        b = await client.post("/api-keys", json={"name": "b"})
        aid, bid = a.json()["id"], b.json()["id"]
        missing = str(uuid.uuid4())
        resp = await client.get(f"/api-keys/batch?ids={aid}&ids={missing}&ids={bid}")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == aid
        assert items[1] is None
        assert items[2]["id"] == bid

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_preserves_duplicate_ids(self, client: AsyncClient) -> None:
        a = await client.post("/api-keys", json={"name": "dup"})
        aid = a.json()["id"]
        resp = await client.get(f"/api-keys/batch?ids={aid}&ids={aid}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == aid
        assert items[1]["id"] == aid

    async def test_batch_all_missing_returns_all_nulls(self, client: AsyncClient) -> None:
        m1, m2 = str(uuid.uuid4()), str(uuid.uuid4())
        resp = await client.get(f"/api-keys/batch?ids={m1}&ids={m2}")
        assert resp.status_code == 200
        assert resp.json()["items"] == [None, None]

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/api-keys/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys/batch?ids=not-a-uuid")
        assert resp.status_code == 422


class TestUpdateApiKeyRoute:
    async def test_update_name(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "old"})
        kid = create.json()["id"]
        resp = await client.patch(f"/api-keys/{kid}", json={"name": "new"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "new"

    async def test_update_enabled(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "k"})
        kid = create.json()["id"]
        token = create.json()["token"]
        # Key works before disabling.
        assert (await client.get("/users", headers={"X-API-Key": token})).status_code == 200
        resp = await client.patch(f"/api-keys/{kid}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        # After disabling, the token no longer authenticates.
        assert (await client.get("/users", headers={"X-API-Key": token})).status_code == 401

    async def test_update_expires_at(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "k"})
        kid = create.json()["id"]
        expires = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        resp = await client.patch(f"/api-keys/{kid}", json={"expires_at": expires})
        assert resp.status_code == 200
        assert resp.json()["expires_at"] is not None

    async def test_update_no_fields(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "keep"})
        kid = create.json()["id"]
        resp = await client.patch(f"/api-keys/{kid}", json={})
        assert resp.status_code == 200
        assert resp.json()["name"] == "keep"

    async def test_update_missing_key_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/api-keys/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404

    async def test_update_empty_name_returns_422(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "k"})
        kid = create.json()["id"]
        resp = await client.patch(f"/api-keys/{kid}", json={"name": "  "})
        assert resp.status_code == 422


class TestDeleteApiKeyRoute:
    async def test_delete_api_key(self, client: AsyncClient) -> None:
        create = await client.post("/api-keys", json={"name": "del"})
        kid = create.json()["id"]
        token = create.json()["token"]
        resp = await client.delete(f"/api-keys/{kid}")
        assert resp.status_code == 204
        assert (await client.get(f"/api-keys/{kid}")).status_code == 404
        # Deleting the row revokes the token.
        assert (await client.get("/users", headers={"X-API-Key": token})).status_code == 401

    async def test_delete_missing_key_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/api-keys/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestBatchWriteApiKeys:
    async def test_batch_mix_cud_returns_positional_results(self, client: AsyncClient) -> None:
        r1 = await client.post("/api-keys", json={"name": "bwr1"})
        r2 = await client.post("/api-keys", json={"name": "bwr2"})
        rid1, rid2 = r1.json()["id"], r2.json()["id"]
        resp = await client.post(
            "/api-keys/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"name": "bwr3"}},
                    {"op": "update", "id": rid1, "data": {"name": "bwr1b"}},
                    {"op": "delete", "id": rid2},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        # Batch create returns a Read (no token field).
        assert items[0]["name"] == "bwr3"
        assert "token" not in items[0]
        assert items[1]["id"] == rid1 and items[1]["name"] == "bwr1b"
        assert items[2] is None
        assert (await client.get(f"/api-keys/{rid2}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        keep = await client.post("/api-keys", json={"name": "bwkeep"})
        resp = await client.post(
            "/api-keys/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"name": "bwrollback"}},
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        assert (await client.get(f"/api-keys/{keep.json()['id']}")).status_code == 200
        keys = (await client.get("/api-keys?limit=100")).json()["items"]
        names = {k["name"] for k in keys}
        assert "bwrollback" not in names

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/api-keys/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_over_100_ops_rejected(self, client: AsyncClient) -> None:
        ops = [{"op": "create", "data": {"name": f"bx{i}"}} for i in range(101)]
        resp = await client.post("/api-keys/batch", json={"operations": ops})
        assert resp.status_code == 422


class TestPermissionEnforcement:
    async def test_missing_auth_token_anonymous_denied(self, app) -> None:
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api-keys")
        assert resp.status_code == 403

    async def test_invalid_auth_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api-keys", headers={"X-API-Key": "not-a-valid-token"})
        assert resp.status_code == 401

    async def test_denied_without_role(self, client: AsyncClient, session) -> None:
        principal = await _make_principal(session, email="norole@example.com", username="norole")
        await session.commit()
        token = create_auth_token(principal.id)

        resp = await client.get("/api-keys", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        resp = await client.post(
            "/api-keys",
            json={"name": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    async def test_allowed_with_permitted_role(self, client: AsyncClient, session) -> None:
        principal = await _make_principal(
            session, email="permitted@example.com", username="permitted"
        )
        await _assign_role(session, principal.id, {"api_key_permission": Permitted()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/api-keys", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    async def test_partial_permission_denies_other_action(
        self, client: AsyncClient, session
    ) -> None:
        principal = await _make_principal(
            session, email="readonly@example.com", username="readonly"
        )
        await _assign_role(session, principal.id, {"api_key_permission": ReadOnly()})
        await session.commit()

        token = create_auth_token(principal.id)
        resp = await client.get("/api-keys", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        resp = await client.post(
            "/api-keys",
            json={"name": "new"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
