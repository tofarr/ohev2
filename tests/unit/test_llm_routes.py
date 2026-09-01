"""Route tests for the LLM feature (DB-backed, ASGI client)."""

from __future__ import annotations

import uuid
from unittest.mock import patch

import httpx
import pytest
import respx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.llm.llm_models import LlmUsage


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
    async def test_missing_llm_returns_404(self, client: AsyncClient) -> None:
        resp = await client.post(
            f"/llm/completion/{uuid.uuid4()}",
            json={"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]},
        )
        assert resp.status_code == 404

    async def test_invalid_messages_returns_422(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        llm = await _create_llm(client, conn["id"])
        resp = await client.post(
            f"/llm/completion/{llm['id']}",
            json={"messages": [{"role": "not-a-role"}]},
        )
        assert resp.status_code == 422

    async def test_completion_proxies_to_sdk(
        self,
        client: AsyncClient,
        session: AsyncSession,
    ) -> None:
        conn = await _create_connection(
            client,
            enable_proxy=True,
            base_url="https://real.example.com",
        )
        llm = await _create_llm(client, conn["id"])

        from unittest.mock import MagicMock

        # A fake SDK LLMResponse: message + metrics + raw_response(id).
        fake_message = MagicMock()
        fake_message.model_dump.return_value = {"role": "assistant", "content": []}
        fake_metrics = MagicMock()
        fake_metrics.model_name = "gpt-4o"
        fake_metrics.model_dump.return_value = {
            "model_name": "gpt-4o",
            "accumulated_cost": 0.1,
            "accumulated_token_usage": {
                "prompt_tokens": 3,
                "completion_tokens": 5,
            },
        }

        fake_response = MagicMock()
        fake_response.id = "resp-123"
        fake_response.message = fake_message
        fake_response.metrics = fake_metrics

        async def _fake_acompletion(self, messages, tools=None, **kwargs):
            assert self.base_url == "https://real.example.com"
            return fake_response

        with patch(
            "openhands.sdk.llm.llm.LLM.acompletion",
            new=_fake_acompletion,
        ):
            resp = await client.post(
                f"/llm/completion/{llm['id']}",
                json={
                    "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        usage = (await session.execute(select(LlmUsage))).scalar_one()
        assert usage.llm_id == uuid.UUID(llm["id"])
        assert usage.provider_connection_id == uuid.UUID(conn["id"])
        assert usage.response_id == "resp-123"
        assert usage.model == "gpt-4o"
        assert usage.prompt_tokens == 3
        assert usage.completion_tokens == 5

        assert body["id"] == "resp-123"
        fake_message.model_dump.assert_called_once()

    async def test_completion_streams_chunks_and_records_usage(
        self,
        client: AsyncClient,
        session: AsyncSession,
    ) -> None:
        conn = await _create_connection(client, base_url="https://real.example.com")
        llm = await _create_llm(client, conn["id"])

        from unittest.mock import MagicMock

        fake_message = MagicMock()
        fake_message.model_dump.return_value = {"role": "assistant", "content": []}
        fake_metrics = MagicMock()
        fake_metrics.model_name = "gpt-4o"
        fake_metrics.model_dump.return_value = {
            "model_name": "gpt-4o",
            "accumulated_cost": 0.2,
            "accumulated_token_usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }
        fake_response = MagicMock()
        fake_response.id = "resp-stream"
        fake_response.message = fake_message
        fake_response.metrics = fake_metrics

        async def _fake_acompletion(self, messages, tools=None, on_token=None, **kwargs):
            assert kwargs["stream"] is True
            assert on_token is not None
            await on_token({"choices": [{"delta": {"content": "hi"}}]})
            return fake_response

        with patch("openhands.sdk.llm.llm.LLM.acompletion", new=_fake_acompletion):
            async with client.stream(
                "POST",
                f"/llm/completion/{llm['id']}",
                json={
                    "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
                    "params": {"stream": True},
                },
            ) as resp:
                body = await resp.aread()

        assert resp.status_code == 200, body
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert b'"content": "hi"' in body
        assert b"data: [DONE]" in body
        usage = (await session.execute(select(LlmUsage))).scalar_one()
        assert usage.response_id == "resp-stream"
        assert usage.prompt_tokens == 2
        assert usage.completion_tokens == 1

    @respx.mock
    async def test_openai_compatible_proxy_records_calculated_cost(
        self,
        client: AsyncClient,
        session: AsyncSession,
    ) -> None:
        conn = await _create_connection(client, base_url="https://real.example.com")
        llm = await _create_llm(
            client,
            conn["id"],
            config={
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000002,
            },
        )
        upstream = respx.post("https://real.example.com/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "chatcmpl-1",
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hello"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 100,
                        "completion_tokens": 50,
                        "total_tokens": 150,
                    },
                },
            )
        )

        resp = await client.post(
            f"/llm/completion/{llm['id']}/chat/completions",
            headers={"authorization": "Bearer sk-test"},
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
        )

        assert resp.status_code == 200, resp.text
        assert upstream.called
        usage = (await session.execute(select(LlmUsage))).scalar_one()
        assert usage.response_id == "chatcmpl-1"
        assert usage.prompt_tokens == 100
        assert usage.completion_tokens == 50
        assert float(usage.accumulated_cost) == pytest.approx(0.0002)


# ====================================================================== #
# Batch read
# ====================================================================== #


class TestBatchReadProviderConnections:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        a = await _create_connection(client, display_name="a")
        b = await _create_connection(client, display_name="b")
        missing = str(uuid.uuid4())
        resp = await client.get(
            f"/llm/provider-connections/batch?ids={a['id']}&ids={missing}&ids={b['id']}"
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == a["id"]
        assert items[1] is None
        assert items[2]["id"] == b["id"]

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/llm/provider-connections/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_preserves_duplicate_ids(self, client: AsyncClient) -> None:
        conn = await _create_connection(client, display_name="dup")
        resp = await client.get(
            f"/llm/provider-connections/batch?ids={conn['id']}&ids={conn['id']}"
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == conn["id"]
        assert items[1]["id"] == conn["id"]

    async def test_batch_all_missing_returns_all_nulls(self, client: AsyncClient) -> None:
        m1, m2 = str(uuid.uuid4()), str(uuid.uuid4())
        resp = await client.get(f"/llm/provider-connections/batch?ids={m1}&ids={m2}")
        assert resp.status_code == 200
        assert resp.json()["items"] == [None, None]

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/llm/provider-connections/batch?{ids}")
        assert resp.status_code == 422

    async def test_batch_invalid_uuid_returns_422(self, client: AsyncClient) -> None:
        resp = await client.get("/llm/provider-connections/batch?ids=not-a-uuid")
        assert resp.status_code == 422


class TestBatchReadLlms:
    async def test_batch_returns_aligned_with_nulls_for_missing(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        a = await _create_llm(client, conn["id"], display_name="a")
        b = await _create_llm(client, conn["id"], display_name="b")
        missing = str(uuid.uuid4())
        resp = await client.get(f"/llm/llms/batch?ids={a['id']}&ids={missing}&ids={b['id']}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == a["id"]
        assert items[1] is None
        assert items[2]["id"] == b["id"]

    async def test_batch_empty_ids_returns_empty_list(self, client: AsyncClient) -> None:
        resp = await client.get("/llm/llms/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_batch_preserves_duplicate_ids(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        llm = await _create_llm(client, conn["id"], display_name="dup")
        resp = await client.get(f"/llm/llms/batch?ids={llm['id']}&ids={llm['id']}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == llm["id"]
        assert items[1]["id"] == llm["id"]

    async def test_batch_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/llm/llms/batch?{ids}")
        assert resp.status_code == 422


# ====================================================================== #
# Batch write
# ====================================================================== #


class TestBatchWriteProviderConnections:
    async def test_batch_mix_cud_returns_positional_results(self, client: AsyncClient) -> None:
        c1 = await _create_connection(client, display_name="bwc1")
        c2 = await _create_connection(client, display_name="bwc2")
        resp = await client.post(
            "/llm/provider-connections/batch",
            json={
                "operations": [
                    {"op": "create", "data": _conn_payload(display_name="bwc3")},
                    {"op": "update", "id": c1["id"], "data": {"display_name": "updated"}},
                    {"op": "delete", "id": c2["id"]},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["display_name"] == "bwc3"
        assert items[1]["id"] == c1["id"] and items[1]["display_name"] == "updated"
        assert items[2] is None
        # delete persisted
        assert (await client.get(f"/llm/provider-connections/{c2['id']}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        keep = await _create_connection(client, display_name="keep")
        before = (await client.get("/llm/provider-connections/count")).json()["count"]
        resp = await client.post(
            "/llm/provider-connections/batch",
            json={
                "operations": [
                    {"op": "create", "data": _conn_payload(display_name="rollback")},
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        after = (await client.get("/llm/provider-connections/count")).json()["count"]
        assert after == before
        assert (await client.get(f"/llm/provider-connections/{keep['id']}")).status_code == 200

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/llm/provider-connections/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_over_100_ops_rejected(self, client: AsyncClient) -> None:
        ops = [{"op": "create", "data": _conn_payload(display_name=f"bx{i}")} for i in range(101)]
        resp = await client.post("/llm/provider-connections/batch", json={"operations": ops})
        assert resp.status_code == 422

    async def test_batch_unknown_op_discriminator_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/llm/provider-connections/batch",
            json={"operations": [{"op": "upsert", "data": _conn_payload(display_name="z")}]},
        )
        assert resp.status_code == 422


class TestBatchWriteLlms:
    async def test_batch_mix_cud_returns_positional_results(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        l1 = await _create_llm(client, conn["id"], display_name="bwl1")
        l2 = await _create_llm(client, conn["id"], display_name="bwl2")
        resp = await client.post(
            "/llm/llms/batch",
            json={
                "operations": [
                    {"op": "create", "data": _llm_payload(conn["id"], display_name="bwl3")},
                    {"op": "update", "id": l1["id"], "data": {"display_name": "updated"}},
                    {"op": "delete", "id": l2["id"]},
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["display_name"] == "bwl3"
        assert items[1]["id"] == l1["id"] and items[1]["display_name"] == "updated"
        assert items[2] is None
        assert (await client.get(f"/llm/llms/{l2['id']}")).status_code == 404

    async def test_batch_atomic_rollback_on_missing_id(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        keep = await _create_llm(client, conn["id"], display_name="keep")
        before = (await client.get("/llm/llms/count")).json()["count"]
        resp = await client.post(
            "/llm/llms/batch",
            json={
                "operations": [
                    {"op": "create", "data": _llm_payload(conn["id"], display_name="rollback")},
                    {"op": "delete", "id": str(uuid.uuid4())},  # missing -> 404
                ]
            },
        )
        assert resp.status_code == 404
        after = (await client.get("/llm/llms/count")).json()["count"]
        assert after == before
        assert (await client.get(f"/llm/llms/{keep['id']}")).status_code == 200

    async def test_batch_empty_operations_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/llm/llms/batch", json={"operations": []})
        assert resp.status_code == 422

    async def test_batch_over_100_ops_rejected(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        ops = [
            {"op": "create", "data": _llm_payload(conn["id"], display_name=f"bx{i}")}
            for i in range(101)
        ]
        resp = await client.post("/llm/llms/batch", json={"operations": ops})
        assert resp.status_code == 422

    async def test_batch_unknown_op_discriminator_rejected(self, client: AsyncClient) -> None:
        conn = await _create_connection(client)
        resp = await client.post(
            "/llm/llms/batch",
            json={
                "operations": [{"op": "upsert", "data": _llm_payload(conn["id"], display_name="z")}]
            },
        )
        assert resp.status_code == 422
