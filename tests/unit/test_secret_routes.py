"""Route tests for the secret feature (DB-backed, via ASGI client).

The default ``client`` fixture is the test principal, whose seeded admin role
carries ``Permitted()`` on every entity column including ``secret_permission``,
so it has full CRUD. A second principal with a ``SecretAccess`` policy (not
``Permitted``) is used to exercise the per-secret grant gating via the
``user_secret_permissions`` and ``role_secret_permissions`` link tables.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.secret.secret_security import SecretAccess
from openhands.ev2.util.auth_token import create_auth_token


def _create_payload(code: str = "API_KEY", value: str = "hunter2") -> dict[str, object]:
    return {"code": code, "value": value, "description": "the api key"}


class TestCreateSecretRoute:
    async def test_create_secret(self, client: AsyncClient) -> None:
        resp = await client.post("/secrets", json=_create_payload("MY_KEY"))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["code"] == "MY_KEY"
        assert uuid.UUID(body["id"])
        # Value is decrypted on read.
        assert body["value"] == "hunter2"
        assert body["description"] == "the api key"
        assert body["created_at"] is not None

    async def test_create_duplicate_code_returns_409(self, client: AsyncClient) -> None:
        await client.post("/secrets", json=_create_payload("DUP"))
        resp = await client.post("/secrets", json=_create_payload("DUP", "other"))
        assert resp.status_code == 409

    async def test_create_invalid_code_returns_422(self, client: AsyncClient) -> None:
        # Codes are letters, digits, underscores only.
        resp = await client.post("/secrets", json=_create_payload("bad code!"))
        assert resp.status_code == 422


class TestGetSecretRoute:
    async def test_get_secret(self, client: AsyncClient) -> None:
        sid = (await client.post("/secrets", json=_create_payload("G"))).json()["id"]
        resp = await client.get(f"/secrets/{sid}")
        assert resp.status_code == 200
        assert resp.json()["value"] == "hunter2"

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/secrets/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        assert (await client.get("/secrets/not-a-uuid")).status_code == 422


class TestListSecretsRoute:
    async def test_search_pagination(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/secrets", json=_create_payload(f"K{i}"))
        resp = await client.get("/secrets?limit=2")
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["next_cursor"] is not None
        rest = await client.get(f"/secrets?limit=2&cursor={body['next_cursor']}")
        assert len(rest.json()["items"]) == 1

    async def test_count(self, client: AsyncClient) -> None:
        await client.post("/secrets", json=_create_payload("CNT"))
        resp = await client.get("/secrets/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1


class TestUpdateSecretRoute:
    async def test_update_value(self, client: AsyncClient) -> None:
        sid = (await client.post("/secrets", json=_create_payload("U"))).json()["id"]
        resp = await client.patch(
            f"/secrets/{sid}", json={"value": "rotated", "description": "new"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["value"] == "rotated"
        assert body["description"] == "new"

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/secrets/{uuid.uuid4()}", json={"description": "x"})
        assert resp.status_code == 404


class TestDeleteSecretRoute:
    async def test_delete_secret(self, client: AsyncClient) -> None:
        sid = (await client.post("/secrets", json=_create_payload("DEL"))).json()["id"]
        assert (await client.delete(f"/secrets/{sid}")).status_code == 204
        assert (await client.get(f"/secrets/{sid}")).status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.delete(f"/secrets/{uuid.uuid4()}")).status_code == 404


class TestSecretBatchRoute:
    async def test_batch_read(self, client: AsyncClient) -> None:
        a = (await client.post("/secrets", json=_create_payload("BA"))).json()["id"]
        b = (await client.post("/secrets", json=_create_payload("BB"))).json()["id"]
        resp = await client.get(f"/secrets/batch?ids={a}&ids={b}&ids={uuid.uuid4()}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items[0]["id"] == a
        assert items[1]["id"] == b
        assert items[2] is None

    async def test_batch_write(self, client: AsyncClient) -> None:
        sid = (await client.post("/secrets", json=_create_payload("BW"))).json()["id"]
        resp = await client.post(
            "/secrets/batch",
            json={
                "operations": [
                    {"op": "create", "data": {"code": "BW2", "value": "v"}},
                    {"op": "update", "id": sid, "data": {"description": "batch-updated"}},
                    {"op": "delete", "id": sid},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        results = resp.json()["items"]
        assert results[0]["code"] == "BW2"
        assert results[1]["description"] == "batch-updated"
        assert results[2] is None


class TestUserSecretPermissionRoute:
    async def test_create_get_update_delete_user_secret_permission(
        self, client: AsyncClient, session
    ) -> None:
        sid = (await client.post("/secrets", json=_create_payload("USP_ROUTE"))).json()["id"]
        principal = await _make_principal(
            session, email="usp-route@example.com", username="usp-route"
        )
        await session.commit()

        created = await client.post(
            "/user-secret-permissions",
            json={"user_id": str(principal.id), "secret_id": sid, "read_enabled": True},
        )
        assert created.status_code == 201, created.text
        grant_id = created.json()["id"]
        assert created.json()["user_id"] == str(principal.id)
        assert created.json()["secret_id"] == sid
        assert created.json()["read_enabled"] is True

        fetched = await client.get(f"/user-secret-permissions/{grant_id}")
        assert fetched.status_code == 200
        updated = await client.patch(
            f"/user-secret-permissions/{grant_id}", json={"update_enabled": True}
        )
        assert updated.status_code == 200
        assert updated.json()["update_enabled"] is True
        deleted = await client.delete(f"/user-secret-permissions/{grant_id}")
        assert deleted.status_code == 204
        assert (await client.get(f"/user-secret-permissions/{grant_id}")).status_code == 404

    async def test_duplicate_user_secret_permission_returns_409(
        self, client: AsyncClient, session
    ) -> None:
        sid = (await client.post("/secrets", json=_create_payload("USP_DUP"))).json()["id"]
        principal = await _make_principal(session, email="usp-dup@example.com", username="usp-dup")
        await session.commit()
        payload = {"user_id": str(principal.id), "secret_id": sid, "read_enabled": True}
        assert (await client.post("/user-secret-permissions", json=payload)).status_code == 201
        assert (await client.post("/user-secret-permissions", json=payload)).status_code == 409

    async def test_search_count_and_batch_read_user_secret_permissions(
        self, client: AsyncClient, session
    ) -> None:
        first = (await client.post("/secrets", json=_create_payload("USP_LIST_A"))).json()["id"]
        second = (await client.post("/secrets", json=_create_payload("USP_LIST_B"))).json()["id"]
        principal = await _make_principal(
            session, email="usp-list@example.com", username="usp-list"
        )
        await session.commit()
        created_ids: list[str] = []
        for sid in (first, second):
            resp = await client.post(
                "/user-secret-permissions",
                json={"user_id": str(principal.id), "secret_id": sid, "read_enabled": True},
            )
            assert resp.status_code == 201, resp.text
            created_ids.append(resp.json()["id"])

        page = await client.get(f"/user-secret-permissions?user_id__eq={principal.id}&limit=1")
        assert page.status_code == 200
        body = page.json()
        assert len(body["items"]) == 1
        assert body["next_cursor"] is not None
        next_page = await client.get(
            f"/user-secret-permissions?user_id__eq={principal.id}&limit=1"
            f"&cursor={body['next_cursor']}"
        )
        assert next_page.status_code == 200
        assert len(next_page.json()["items"]) == 1

        count = await client.get(f"/user-secret-permissions/count?user_id__eq={principal.id}")
        assert count.status_code == 200
        assert count.json()["count"] == 2

        batch = await client.get(
            f"/user-secret-permissions/batch?ids={created_ids[0]}&ids={uuid.uuid4()}"
        )
        assert batch.status_code == 200
        items = batch.json()["items"]
        assert items[0]["id"] == created_ids[0]
        assert items[1] is None

    async def test_user_secret_permission_invalid_cursor_returns_400(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get("/user-secret-permissions?cursor=not-a-uuid")
        assert resp.status_code == 400

    async def test_user_secret_permission_batch_read_rejects_too_many_ids(
        self, client: AsyncClient
    ) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/user-secret-permissions/batch?{ids}")
        assert resp.status_code == 422

    async def test_create_user_secret_permission_orphan_returns_404(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/user-secret-permissions",
            json={
                "user_id": str(uuid.uuid4()),
                "secret_id": str(uuid.uuid4()),
                "read_enabled": True,
            },
        )
        assert resp.status_code == 404

    async def test_update_delete_missing_user_secret_permission_returns_404(
        self, client: AsyncClient
    ) -> None:
        missing = uuid.uuid4()
        assert (
            await client.patch(f"/user-secret-permissions/{missing}", json={"read_enabled": True})
        ).status_code == 404
        assert (await client.delete(f"/user-secret-permissions/{missing}")).status_code == 404

    async def test_batch_write_user_secret_permissions(self, client: AsyncClient, session) -> None:
        first = (await client.post("/secrets", json=_create_payload("USP_BATCH_A"))).json()["id"]
        second = (await client.post("/secrets", json=_create_payload("USP_BATCH_B"))).json()["id"]
        principal = await _make_principal(
            session, email="usp-batch@example.com", username="usp-batch"
        )
        await session.commit()
        existing = await client.post(
            "/user-secret-permissions",
            json={"user_id": str(principal.id), "secret_id": first, "read_enabled": True},
        )
        assert existing.status_code == 201, existing.text
        existing_id = existing.json()["id"]
        resp = await client.post(
            "/user-secret-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "user_id": str(principal.id),
                            "secret_id": second,
                            "delete_enabled": True,
                        },
                    },
                    {"op": "update", "id": existing_id, "data": {"update_enabled": True}},
                    {"op": "delete", "id": existing_id},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["delete_enabled"] is True
        assert items[1]["update_enabled"] is True
        assert items[2] is None

    async def test_batch_write_user_secret_permission_conflict_returns_409(
        self, client: AsyncClient, session
    ) -> None:
        sid = (await client.post("/secrets", json=_create_payload("USP_BATCH_DUP"))).json()["id"]
        principal = await _make_principal(
            session, email="usp-batch-dup@example.com", username="usp-batch-dup"
        )
        await session.commit()
        payload = {"user_id": str(principal.id), "secret_id": sid, "read_enabled": True}
        assert (await client.post("/user-secret-permissions", json=payload)).status_code == 201
        resp = await client.post(
            "/user-secret-permissions/batch",
            json={"operations": [{"op": "create", "data": payload}]},
        )
        assert resp.status_code == 409

    async def test_batch_write_user_secret_permission_orphan_returns_404(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/user-secret-permissions/batch",
            json={
                "operations": [
                    {
                        "op": "create",
                        "data": {
                            "user_id": str(uuid.uuid4()),
                            "secret_id": str(uuid.uuid4()),
                            "read_enabled": True,
                        },
                    }
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_write_user_secret_permission_missing_returns_404(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(
            "/user-secret-permissions/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(uuid.uuid4()), "data": {"read_enabled": True}}
                ]
            },
        )
        assert resp.status_code == 404

    async def test_direct_user_grant_allows_secret_access(
        self, client: AsyncClient, session
    ) -> None:
        sid = (await client.post("/secrets", json=_create_payload("USP_ACCESS"))).json()["id"]
        principal = await _make_principal(
            session, email="usp-access@example.com", username="usp-access"
        )
        await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        grant = await client.post(
            "/user-secret-permissions",
            json={"user_id": str(principal.id), "secret_id": sid, "read_enabled": True},
        )
        assert grant.status_code == 201, grant.text
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["value"] == "hunter2"


class TestSecretAccessPolicy:
    """A ``SecretAccess`` principal is gated by user and role grant rows."""

    async def test_create_allowed_without_grant(self, client: AsyncClient, session) -> None:
        # SecretAccess permits CREATE regardless of grants (no secret id yet).
        principal = await _make_principal(
            session, email="sa-create@example.com", username="sa-create"
        )
        await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.post(
            "/secrets",
            json=_create_payload("SA_CREATE"),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201, resp.text
        sid = resp.json()["id"]
        read = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        assert read.status_code == 200

    async def test_read_denied_without_grant(self, client: AsyncClient, session) -> None:
        # Admin creates a secret; this principal has no matching user or role grant.
        sid = (await client.post("/secrets", json=_create_payload("SA_READ"))).json()["id"]
        principal = await _make_principal(session, email="sa-read@example.com", username="sa-read")
        await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404

    async def test_read_allowed_with_grant(self, client: AsyncClient, session) -> None:
        sid = (await client.post("/secrets", json=_create_payload("SA_GRANT"))).json()["id"]
        principal = await _make_principal(
            session, email="sa-grant@example.com", username="sa-grant"
        )
        role = await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        # Admin grants read on the secret to the other principal's role.
        grant = await client.post(
            "/role-secret-permissions",
            json={"role_id": str(role.id), "secret_id": sid, "read_enabled": True},
        )
        assert grant.status_code == 201, grant.text
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["value"] == "hunter2"
