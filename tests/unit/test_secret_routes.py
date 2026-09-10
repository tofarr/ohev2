"""Route tests for the secret feature (DB-backed, via ASGI client).

The default ``client`` fixture is the test principal, whose seeded admin role
carries ``Permitted()`` on every entity column including ``secret_permission``,
so it has full CRUD. Item-level access control is now handled by the generic
:class:`AclPermission` policy stored in the role's JSONB ``secret_permission``
column — the per-secret link tables have been removed.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import AclPermission, Permitted
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
        assert body["type"] == "static"
        # /secrets returns metadata only — value is never present.
        assert "value" not in body
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
        # /secrets returns metadata only — value is never present.
        assert "value" not in resp.json()

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
        assert "value" not in body
        assert body["description"] == "new"
        # The rotated value is revealed via /secret-values (admin has value permission).
        revealed = await client.get(f"/secret-values/{sid}")
        assert revealed.status_code == 200
        assert revealed.json()["value"] == "rotated"

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


class TestSecretAclPolicy:
    """A principal with an ``AclPermission`` on ``secret_permission`` is gated
    by the item id list — no link tables involved."""

    async def test_read_denied_without_permitted_id(self, client: AsyncClient, session) -> None:
        sid = (await client.post("/secrets", json=_create_payload("ACL_READ"))).json()["id"]
        principal = await _make_principal(
            session, email="acl-read@example.com", username="acl-read"
        )
        await _assign_role(
            session,
            principal.id,
            {"secret_permission": AclPermission(item_ids=[], on_match=Permitted())},
        )
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        # Empty item_ids => on_mismatch (default Denied) => 403.
        assert resp.status_code == 403

    async def test_read_allowed_with_permitted_id(self, client: AsyncClient, session) -> None:
        sid = (await client.post("/secrets", json=_create_payload("ACL_OK"))).json()["id"]
        principal = await _make_principal(session, email="acl-ok@example.com", username="acl-ok")
        await _assign_role(
            session,
            principal.id,
            {"secret_permission": AclPermission(item_ids=[uuid.UUID(sid)], on_match=Permitted())},
        )
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        # /secrets returns metadata only — value is absent.
        assert "value" not in resp.json()
        # ACL-only principals (no secret_value_permission) cannot reveal.
        reveal = await client.get(
            f"/secret-values/{sid}", headers={"Authorization": f"Bearer {token}"}
        )
        assert reveal.status_code == 403


class TestSecretValueRoute:
    """The /secret-values projection reveals plaintext (admin principal has
    secret_value_permission=Permitted() via the seeded admin role)."""

    async def test_reveal_value(self, client: AsyncClient) -> None:
        sid = (await client.post("/secrets", json=_create_payload("RV"))).json()["id"]
        resp = await client.get(f"/secret-values/{sid}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == sid
        assert body["code"] == "RV"
        assert body["type"] == "static"
        assert body["value"] == "hunter2"

    async def test_reveal_missing_returns_404(self, client: AsyncClient) -> None:
        assert (await client.get(f"/secret-values/{uuid.uuid4()}")).status_code == 404

    async def test_reveal_search(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/secrets", json=_create_payload(f"VS{i}"))
        resp = await client.get("/secret-values?limit=2")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert all("value" in item for item in body["items"])
        assert body["next_cursor"] is not None

    async def test_reveal_batch(self, client: AsyncClient) -> None:
        a = (await client.post("/secrets", json=_create_payload("VBA"))).json()["id"]
        b = (await client.post("/secrets", json=_create_payload("VBB"))).json()["id"]
        resp = await client.get(f"/secret-values/batch?ids={a}&ids={b}&ids={uuid.uuid4()}")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["id"] == a and items[0]["value"] == "hunter2"
        assert items[1]["id"] == b and items[1]["value"] == "hunter2"
        assert items[2] is None

    async def test_reveal_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        assert (await client.get("/secret-values?cursor=not-a-uuid")).status_code == 400

    async def test_reveal_batch_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        assert (await client.get(f"/secret-values/batch?{ids}")).status_code == 422


class TestSecretRouteErrorPaths:
    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        assert (await client.get("/secrets?cursor=not-a-uuid")).status_code == 400

    async def test_batch_read_too_many_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        assert (await client.get(f"/secrets/batch?{ids}")).status_code == 422

    async def test_batch_write_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/secrets/batch",
            json={
                "operations": [
                    {"op": "update", "id": str(uuid.uuid4()), "data": {"value": "x"}},
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_write_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/secrets/batch",
            json={
                "operations": [
                    {"op": "delete", "id": str(uuid.uuid4())},
                ]
            },
        )
        assert resp.status_code == 404

    async def test_batch_write_duplicate_returns_409(self, client: AsyncClient) -> None:
        resp1 = await client.post("/secrets", json=_create_payload("DUP_BATCH"))
        assert resp1.status_code == 201
        secret_id = resp1.json()["id"]
        resp = await client.post(
            "/secrets/batch",
            json={
                "operations": [
                    {"op": "create", "data": _create_payload("DUP_BATCH", "other")},
                    {"op": "delete", "id": secret_id},
                ]
            },
        )
        assert resp.status_code == 409

    async def test_batch_empty_ops_rejected(self, client: AsyncClient) -> None:
        assert (await client.post("/secrets/batch", json={"operations": []})).status_code == 422
