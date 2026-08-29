"""Route tests for the secret feature (DB-backed, via ASGI client).

The default ``client`` fixture is the test principal, whose seeded admin role
carries ``Permitted()`` on every entity column including ``secret_permission``,
so it has full CRUD. A second principal with a ``SecretAccess`` policy (not
``Permitted``) is used to exercise the per-secret grant gating via the
``role_secrets`` link table.
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


class TestSecretAccessPolicy:
    """A principal whose role carries ``SecretAccess`` (not ``Permitted``) is
    gated per-secret by the ``role_secrets`` link table."""

    async def test_create_allowed_without_grant(self, client: AsyncClient, session) -> None:
        # SecretAccess permits CREATE regardless of grants (no secret id yet).
        principal = await _make_principal(
            session, email="sa-create@example.com", username="sa-create"
        )
        await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.post(
            "/secrets", json=_create_payload("SA_CREATE"), headers={"X-API-Key": token}
        )
        assert resp.status_code == 201, resp.text

    async def test_read_denied_without_grant(self, client: AsyncClient, session) -> None:
        # Admin creates a secret; the SecretAccess principal cannot read it
        # without a role_secrets row with read_enabled.
        sid = (await client.post("/secrets", json=_create_payload("SA_READ"))).json()["id"]
        principal = await _make_principal(session, email="sa-read@example.com", username="sa-read")
        await _assign_role(session, principal.id, {"secret_permission": SecretAccess()})
        await session.commit()
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"X-API-Key": token})
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
            "/role-secrets",
            json={"role_id": str(role.id), "secret_id": sid, "read_enabled": True},
        )
        assert grant.status_code == 201, grant.text
        token = create_auth_token(principal.id)
        resp = await client.get(f"/secrets/{sid}", headers={"X-API-Key": token})
        assert resp.status_code == 200
        assert resp.json()["value"] == "hunter2"
