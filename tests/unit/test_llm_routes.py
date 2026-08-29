"""Route tests for the LLM feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid
from unittest.mock import patch

from httpx import AsyncClient


def _conn_payload(**overrides) -> dict:
    payload: dict = {
        "display_name": "my-conn",
        "provider": "custom",
        "api_key": "sk-test",
        "base_url": "https://real.example.com",
        "enable_proxy": False,
    }
    payload.update(overrides)
    return payload


def _llm_payload(connection_id: str, **overrides) -> dict:
    payload: dict = {
        "provider_connection_id": connection_id,
        "model": "gpt-4o",
        "display_name": "my-llm",
        "config": {},
    }
    payload.update(overrides)
    return payload


async def _create_connection(client: AsyncClient, **overrides) -> dict:
    resp = await client.post("/llm/provider-connections", json=_conn_payload(**overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_llm(client: AsyncClient, connection_id: str, **overrides) -> dict:
    resp = await client.post("/llm/llms", json=_llm_payload(connection_id, **overrides))
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestProviderConnectionCrud:
    async def test_create_and_get(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        assert conn["display_name"] == "my-conn"
        assert "api_key" not in conn  # write-only
        assert conn["enable_proxy"] is False
        got = await client.get(f"/llm/provider-connections/{conn['id']}")
        assert got.status_code == 200
        assert got.json()["id"] == conn["id"]

    async def test_list_and_count(self, client: AsyncClient) -> None:
        await _create_connection(client, display_name="a")
        await _create_connection(client, display_name="b")
        listed = await client.get("/llm/provider-connections")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 2
        counted = await client.get("/llm/provider-connections/count")
        assert counted.status_code == 200
        assert counted.json()["count"] >= 2

    async def test_search_filter(self, client: AsyncClient) -> None:
        await _create_connection(client, display_name="findme")
        await _create_connection(client, display_name="other")
        resp = await client.get(
            "/llm/provider-connections", params={"display_name__contains": "find"}
        )
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["display_name"] == "findme"

    async def test_update(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        resp = await client.patch(
            f"/llm/provider-connections/{conn['id']}",
            json={"display_name": "renamed", "enable_proxy": True, "api_key": "rotated"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["display_name"] == "renamed"
        assert body["enable_proxy"] is True

    async def test_delete(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        resp = await client.delete(f"/llm/provider-connections/{conn['id']}")
        assert resp.status_code == 204
        assert (await client.get(f"/llm/provider-connections/{conn['id']}")).status_code == 404

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/llm/provider-connections/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestLLMCrud:
    async def test_create_and_get(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        llm = await _create_llm(client, conn["id"])
        assert llm["model"] == "gpt-4o"
        got = await client.get(f"/llm/llms/{llm['id']}")
        assert got.status_code == 200
        assert got.json()["model"] == "gpt-4o"

    async def test_create_invalid_connection_returns_403(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/llm/llms",
            json=_llm_payload(str(uuid.uuid4())),
        )
        assert resp.status_code == 403

    async def test_create_invalid_config_returns_422(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        resp = await client.post(
            "/llm/llms",
            json=_llm_payload(conn["id"], config={"num_retries": -1}),
        )
        assert resp.status_code == 422

    async def test_list_and_count(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        await _create_llm(client, conn["id"])
        listed = await client.get("/llm/llms")
        assert listed.status_code == 200
        assert len(listed.json()["items"]) >= 1
        counted = await client.get("/llm/llms/count")
        assert counted.json()["count"] >= 1

    async def test_update(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        llm = await _create_llm(client, conn["id"])
        resp = await client.patch(
            f"/llm/llms/{llm['id']}",
            json={"display_name": "renamed", "config": {"temperature": 0.2}},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["display_name"] == "renamed"
        assert body["config"] == {"temperature": 0.2}

    async def test_delete(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        llm = await _create_llm(client, conn["id"])
        resp = await client.delete(f"/llm/llms/{llm['id']}")
        assert resp.status_code == 204
        assert (await client.get(f"/llm/llms/{llm['id']}")).status_code == 404


class TestCompletion:
    async def test_missing_connection_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/llm/completion/{uuid.uuid4()}",
            json={"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]},
        )
        assert resp.status_code == 404

    async def test_no_llm_returns_404(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        resp = await client.post(
            f"/llm/completion/{conn['id']}",
            json={"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]},
        )
        assert resp.status_code == 404

    async def test_invalid_messages_returns_422(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        await _create_llm(client, conn["id"])
        resp = await client.post(
            f"/llm/completion/{conn['id']}",
            json={"messages": [{"role": "not-a-role"}]},
        )
        assert resp.status_code == 422

    async def test_completion_proxies_to_sdk(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        await _create_llm(client, conn["id"])

        from unittest.mock import MagicMock

        # A fake SDK LLMResponse: message + metrics + raw_response(id).
        fake_message = MagicMock()
        fake_message.model_dump.return_value = {"role": "assistant", "content": []}
        fake_metrics = MagicMock()
        fake_metrics.model_dump.return_value = {"tokens": 1}

        fake_response = MagicMock()
        fake_response.id = "resp-123"
        fake_response.message = fake_message
        fake_response.metrics = fake_metrics

        async def _fake_acompletion(self, messages, tools=None, **kwargs):
            return fake_response

        with patch(
            "openhands.sdk.llm.llm.LLM.acompletion",
            new=_fake_acompletion,
        ):
            resp = await client.post(
                f"/llm/completion/{conn['id']}",
                json={
                    "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == "resp-123"
        fake_message.model_dump.assert_called_once()
