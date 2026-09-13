"""Route tests for the ``/static-secrets`` CRUD surface."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


def _payload(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "API_KEY",
        "value": "hunter2",
    }
    data.update(overrides)
    return data


async def _create_secret(client: AsyncClient, **overrides: object) -> dict[str, object]:
    response = await client.post("/static-secrets", json=_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


class TestStaticSecretRoutes:
    async def test_full_crud_without_value(self, client: AsyncClient) -> None:
        created = await _create_secret(client)
        secret_id = str(created["id"])

        # The value must never be present in CRUD responses.
        assert created["name"] == "API_KEY"
        assert "value" not in created

        get_response = await client.get(f"/static-secrets/{secret_id}")
        assert get_response.status_code == 200, get_response.text
        assert "value" not in get_response.json()

        batch_response = await client.get("/static-secrets/batch", params={"ids": secret_id})
        assert batch_response.status_code == 200, batch_response.text
        assert "value" not in batch_response.json()["items"][0]

        patch_response = await client.patch(
            f"/static-secrets/{secret_id}",
            json={"name": "ROTATED_KEY", "value": "new-secret"},
        )
        assert patch_response.status_code == 200, patch_response.text
        assert patch_response.json()["name"] == "ROTATED_KEY"
        assert "value" not in patch_response.json()

        delete_response = await client.delete(f"/static-secrets/{secret_id}")
        assert delete_response.status_code == 204, delete_response.text
        assert (await client.get(f"/static-secrets/{secret_id}")).status_code == 404

    async def test_search_filter_count_and_pagination(self, client: AsyncClient) -> None:
        tag = f"KEY_{uuid.uuid4().hex[:8].upper()}"
        created = await _create_secret(client, name=tag)

        search_response = await client.get("/static-secrets", params={"name__contains": tag[:8]})
        assert search_response.status_code == 200, search_response.text
        assert any(i["id"] == created["id"] for i in search_response.json()["items"])

        count_response = await client.get("/static-secrets/count")
        assert count_response.status_code == 200, count_response.text
        assert count_response.json()["count"] >= 1

        invalid_cursor = await client.get("/static-secrets", params={"cursor": "zzz"})
        assert invalid_cursor.status_code == 400

    async def test_invalid_name_returns_422(self, client: AsyncClient) -> None:
        response = await client.post("/static-secrets", json=_payload(name="lower-case"))
        assert response.status_code == 422

    async def test_duplicate_name_conflict(self, client: AsyncClient) -> None:
        await _create_secret(client)
        response = await client.post("/static-secrets", json=_payload(name="API_KEY"))
        assert response.status_code == 409

    async def test_missing_returns_404(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        assert (await client.get(f"/static-secrets/{missing}")).status_code == 404
        assert (
            await client.patch(f"/static-secrets/{missing}", json={"name": "KEY_X"})
        ).status_code == 404
        assert (await client.delete(f"/static-secrets/{missing}")).status_code == 404

    async def test_batch_write_and_read_cap(self, client: AsyncClient) -> None:
        create_response = await client.post(
            "/static-secrets/batch",
            json={"operations": [{"op": "create", "data": _payload(name="BATCH_KEY")}]},
        )
        assert create_response.status_code == 200, create_response.text
        item = create_response.json()["items"][0]
        assert "value" not in item
        secret_id = item["id"]

        update_delete = await client.post(
            "/static-secrets/batch",
            json={
                "operations": [
                    {"op": "update", "id": secret_id, "data": {"name": "BATCH_KEY_2"}},
                    {"op": "delete", "id": secret_id},
                ]
            },
        )
        assert update_delete.status_code == 200, update_delete.text
        assert update_delete.json()["items"][0]["name"] == "BATCH_KEY_2"
        assert update_delete.json()["items"][1] is None

        missing = str(uuid.uuid4())
        update_missing = await client.post(
            "/static-secrets/batch",
            json={"operations": [{"op": "update", "id": missing, "data": {"name": "X"}}]},
        )
        assert update_missing.status_code == 404

        empty = await client.post("/static-secrets/batch", json={"operations": []})
        assert empty.status_code == 422

        too_many_ids = await client.get(
            "/static-secrets/batch",
            params=[("ids", str(uuid.uuid4())) for _ in range(101)],
        )
        assert too_many_ids.status_code == 422


class TestAnonymous:
    async def test_anonymous_write_denied(self, client: AsyncClient) -> None:
        # Batch write requires an authenticated principal even though the
        # per-action dependencies use ``depends_permissions_or_none``.
        from httpx import AsyncClient

        async with AsyncClient(base_url="http://test", transport=client._transport) as anon:
            resp = await anon.post(
                "/static-secrets/batch",
                json={"operations": [{"op": "create", "data": _payload(name="ANON_KEY")}]},
            )
            assert resp.status_code == 401


class TestStaticSecretAccessPolicy:
    """Static secret access is governed by ``static_secret_permission``."""

    async def test_scoped_read_and_deny(self, client: AsyncClient, session) -> None:
        created = await _create_secret(client)

        restricted = await _make_principal(
            session, email="ss-restricted@example.com", username="ss-restricted"
        )
        await _assign_role(
            session,
            restricted.id,
            {"static_secret_permission": ReadOnly()},
            role_name="restricted-ss",
        )
        other = await _make_principal(session, email="ss-other@example.com", username="ss-other")
        await session.commit()

        read_headers = {"Authorization": f"Bearer {create_auth_token(restricted.id)}"}
        assert (
            await client.get(f"/static-secrets/{created['id']}", headers=read_headers)
        ).status_code == 200

        no_role_headers = {"Authorization": f"Bearer {create_auth_token(other.id)}"}
        assert (
            await client.get(f"/static-secrets/{created['id']}", headers=no_role_headers)
        ).status_code == 403

    async def test_create_denied_without_permission(self, client: AsyncClient, session) -> None:
        restricted = await _make_principal(session, email="ss-deny@example.com", username="ss-deny")
        headers = {"Authorization": f"Bearer {create_auth_token(restricted.id)}"}
        resp = await client.post("/static-secrets", json=_payload(name="DENY_KEY"), headers=headers)
        assert resp.status_code == 403

        await _assign_role(
            session,
            restricted.id,
            {"static_secret_permission": Permitted()},
            role_name="ss-full",
        )
        await session.commit()
        resp = await client.post("/static-secrets", json=_payload(name="DENY_KEY"), headers=headers)
        assert resp.status_code == 201, resp.text
