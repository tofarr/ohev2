"""Route tests for the ``/secret-providers`` governed resource."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from tests.unit._auth_helpers import assign_role as _assign_role
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.security.security_models import Permitted, ReadOnly
from openhands.ev2.util.auth_token import create_auth_token


def _payload(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "kind": "static",
        "data": {"token": "plaintext-token", "region": "us-east-1"},
    }
    data.update(overrides)
    return data


async def _create_provider(client: AsyncClient, **overrides: object) -> dict[str, object]:
    response = await client.post("/secret-providers", json=_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


class TestSecretProviderRoutes:
    async def test_full_crud(self, client: AsyncClient) -> None:
        created = await _create_provider(client)
        provider_id = str(created["id"])

        # The response masks every data value.
        assert created["data"] == {"token": "**********", "region": "**********"}
        assert created["kind"] == "static"

        get_response = await client.get(f"/secret-providers/{provider_id}")
        assert get_response.status_code == 200, get_response.text
        assert get_response.json()["id"] == provider_id

        batch_response = await client.get("/secret-providers/batch", params={"ids": provider_id})
        assert batch_response.status_code == 200, batch_response.text
        items = batch_response.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == provider_id

        patch_response = await client.patch(
            f"/secret-providers/{provider_id}",
            json={"data": {"token": "rotated"}},
        )
        assert patch_response.status_code == 200, patch_response.text
        assert patch_response.json()["data"] == {"token": "**********"}

        delete_response = await client.delete(f"/secret-providers/{provider_id}")
        assert delete_response.status_code == 204, delete_response.text
        assert (await client.get(f"/secret-providers/{provider_id}")).status_code == 404

    async def test_search_filter_count_and_pagination(self, client: AsyncClient) -> None:
        tag = f"sp-{uuid.uuid4()}"
        response = await client.post(
            "/secret-providers", json=_payload(data={"token": "t", "tag": tag})
        )
        assert response.status_code == 201, response.text
        created = response.json()

        search_response = await client.get("/secret-providers", params={"limit": 5})
        assert search_response.status_code == 200, search_response.text
        assert any(i["id"] == created["id"] for i in search_response.json()["items"])

        count_response = await client.get("/secret-providers/count")
        assert count_response.status_code == 200, count_response.text
        assert count_response.json()["count"] >= 1

        invalid_cursor = await client.get("/secret-providers", params={"cursor": "zzz"})
        assert invalid_cursor.status_code == 400

    async def test_invalid_cursor_returns_400(self, client: AsyncClient) -> None:
        response = await client.get("/secret-providers", params={"cursor": "not-a-uuid"})
        assert response.status_code == 400

    async def test_invalid_kind_returns_422(self, client: AsyncClient) -> None:
        response = await client.post("/secret-providers", json=_payload(kind="aws_sm"))
        assert response.status_code == 422

    async def test_missing_returns_404(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        assert (await client.get(f"/secret-providers/{missing}")).status_code == 404
        assert (
            await client.patch(f"/secret-providers/{missing}", json={"data": {"k": "v"}})
        ).status_code == 404
        assert (await client.delete(f"/secret-providers/{missing}")).status_code == 404

    async def test_batch_write(self, client: AsyncClient) -> None:
        create_response = await client.post(
            "/secret-providers/batch",
            json={
                "operations": [
                    {"op": "create", "data": _payload()},
                ]
            },
        )
        assert create_response.status_code == 200, create_response.text
        item = create_response.json()["items"][0]
        assert item["data"] == {"token": "**********", "region": "**********"}
        provider_id = item["id"]

        # Update + delete in one batch against the created provider.
        update_delete = await client.post(
            "/secret-providers/batch",
            json={
                "operations": [
                    {"op": "update", "id": provider_id, "data": {"data": {"k": "new"}}},
                    {"op": "delete", "id": provider_id},
                ]
            },
        )
        assert update_delete.status_code == 200, update_delete.text
        items = update_delete.json()["items"]
        assert items[0]["data"] == {"k": "**********"}
        assert items[1] is None

    async def test_batch_write_missing_and_empty(self, client: AsyncClient) -> None:
        missing = str(uuid.uuid4())
        update_missing = await client.post(
            "/secret-providers/batch",
            json={"operations": [{"op": "update", "id": missing, "data": {"data": {}}}]},
        )
        assert update_missing.status_code == 404

        delete_missing = await client.post(
            "/secret-providers/batch",
            json={"operations": [{"op": "delete", "id": missing}]},
        )
        assert delete_missing.status_code == 404

        empty = await client.post("/secret-providers/batch", json={"operations": []})
        assert empty.status_code == 422

    async def test_batch_read_cap(self, client: AsyncClient) -> None:
        too_many = await client.get(
            "/secret-providers/batch",
            params=[("ids", str(uuid.uuid4())) for _ in range(101)],
        )
        assert too_many.status_code == 422


class TestSeed:
    async def test_anonymous_write_denied(self, client: AsyncClient) -> None:
        # Batch write requires an authenticated principal even though the
        # per-action dependencies use ``depends_permissions_or_none``.
        from httpx import AsyncClient

        async with AsyncClient(base_url="http://test", transport=client._transport) as anon:
            resp = await anon.post(
                "/secret-providers/batch",
                json={"operations": [{"op": "create", "data": _payload()}]},
            )
            assert resp.status_code == 401


class TestSecretProviderAccessPolicy:
    """Provider access is governed by ``secret_provider_permission``."""

    async def _seed_provider_for(self, client: AsyncClient, session) -> dict[str, object]:
        restricted = await _make_principal(
            session, email="sp-restricted@example.com", username="sp-restricted"
        )
        created = await _create_provider(client)
        await session.commit()
        return created, restricted

    async def test_scoped_read_and_match(self, client: AsyncClient, session) -> None:
        created, restricted = await self._seed_provider_for(client, session)
        await _assign_role(
            session,
            restricted.id,
            {"secret_provider_permission": ReadOnly()},
            role_name="restricted-prov",
        )
        await session.commit()
        headers = {"Authorization": f"Bearer {create_auth_token(restricted.id)}"}

        resp = await client.get(f"/secret-providers/{created['id']}", headers=headers)
        assert resp.status_code == 200, resp.text

        # A user without the permission cannot read.
        other = await _make_principal(session, email="sp-other@example.com", username="sp-other")
        no_role_headers = {"Authorization": f"Bearer {create_auth_token(other.id)}"}
        assert (
            await client.get(f"/secret-providers/{created['id']}", headers=no_role_headers)
        ).status_code == 403

    async def test_create_denied_without_permission(self, client: AsyncClient, session) -> None:
        restricted = await _make_principal(session, email="sp-deny@example.com", username="sp-deny")
        headers = {"Authorization": f"Bearer {create_auth_token(restricted.id)}"}
        resp = await client.post("/secret-providers", json=_payload(), headers=headers)
        assert resp.status_code == 403

        await _assign_role(
            session,
            restricted.id,
            {"secret_provider_permission": Permitted()},
            role_name="sp-full",
        )
        await session.commit()
        resp = await client.post("/secret-providers", json=_payload(), headers=headers)
        assert resp.status_code == 201, resp.text
