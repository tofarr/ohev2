"""Tests for app.py — background lifespan loops and app construction."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from openhands.ev2.app import (
    _background_sweep,
    _cleanup_loop,
    _llm_usage_aggregate_loop,
    _llm_usage_partition_loop,
    _mcp_usage_aggregate_loop,
    _mcp_usage_partition_loop,
    _partition_message,
    _sandbox_usage_loop,
    _sweep_expired_tokens,
    _sweep_llm_aggregate,
    _sweep_llm_partitions,
    _sweep_mcp_aggregate,
    _sweep_mcp_partitions,
    _sweep_sandbox_usage,
    create_app,
    lifespan,
)


class TestCreateApp:
    def test_create_app_includes_dev_router_by_default(self) -> None:
        app = create_app()
        paths = set()
        for r in app.routes:
            p = getattr(r, "path", None)
            if p:
                paths.add(p)
        assert "/health" in paths

    def test_create_app_has_middleware(self) -> None:
        app = create_app()
        middleware_names = [m.cls.__name__ for m in app.user_middleware]
        assert "CorsMiddleware" in middleware_names


class TestCleanupLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.cleanup_interval = 0
            await _cleanup_loop()

    async def test_sweep_deletes_expired_tokens(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.cleanup_interval = 0.01
            mock_service = AsyncMock()
            mock_service.delete_expired_tokens.return_value = 3
            mock_service.aclose = AsyncMock()

            class FakeAuthService:
                def __init__(self, session):
                    pass

                delete_expired_tokens = mock_service.delete_expired_tokens
                aclose = mock_service.aclose

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=mock_service)
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch("openhands.ev2.auth.auth_service.AuthService", FakeAuthService):
                task = asyncio.create_task(_cleanup_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.cleanup_interval = 0.01
            mock_factory.side_effect = RuntimeError("db down")

            task = asyncio.create_task(_cleanup_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestLlmUsagePartitionLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.llm.usage.partition_interval = 0
            await _llm_usage_partition_loop()

    async def test_sweep_creates_and_drops_partitions(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.llm.usage.partition_interval = 0.01
            mock_cfg.return_value.llm.usage.preallocate_days = 3
            mock_cfg.return_value.llm.usage.retention_days = 30

            class FakeService:
                async def ensure_partitions(self, *, preallocate_days, retention_days):
                    return (["p1"], ["p2"])

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=FakeService())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch("openhands.ev2.llm.llm_usage_service.LlmUsageService", FakeService):
                task = asyncio.create_task(_llm_usage_partition_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.llm.usage.partition_interval = 0.01
            mock_factory.side_effect = RuntimeError("db down")

            task = asyncio.create_task(_llm_usage_partition_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestLlmUsageAggregateLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.llm.usage.aggregate_interval = 0
            await _llm_usage_aggregate_loop()

    async def test_sweep_aggregates_usage(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.llm.usage.aggregate_interval = 0.01

            class FakeService:
                async def aggregate_behind_now(self, *, lag_minutes=1):
                    return 5

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=FakeService())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch("openhands.ev2.llm.llm_usage_service.LlmUsageService", FakeService):
                task = asyncio.create_task(_llm_usage_aggregate_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.llm.usage.aggregate_interval = 0.01
            mock_factory.side_effect = RuntimeError("db down")

            task = asyncio.create_task(_llm_usage_aggregate_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestMcpUsagePartitionLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.mcp.usage.partition_interval = 0
            await _mcp_usage_partition_loop()

    async def test_sweep_creates_and_drops_partitions(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.mcp.usage.partition_interval = 0.01
            mock_cfg.return_value.mcp.usage.preallocate_days = 3
            mock_cfg.return_value.mcp.usage.retention_days = 30

            class FakeService:
                async def ensure_partitions(self, *, preallocate_days, retention_days):
                    return (["p1"], ["p2"])

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=FakeService())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch(
                "openhands.ev2.mcp_server_config.mcp_usage_service.McpUsageService", FakeService
            ):
                task = asyncio.create_task(_mcp_usage_partition_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.mcp.usage.partition_interval = 0.01
            mock_factory.side_effect = RuntimeError("db down")

            task = asyncio.create_task(_mcp_usage_partition_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestMcpUsageAggregateLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.mcp.usage.aggregate_interval = 0
            await _mcp_usage_aggregate_loop()

    async def test_sweep_aggregates_usage(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.mcp.usage.aggregate_interval = 0.01

            class FakeService:
                async def aggregate_behind_now(self, *, lag_minutes=1):
                    return 5

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=FakeService())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch(
                "openhands.ev2.mcp_server_config.mcp_usage_service.McpUsageService", FakeService
            ):
                task = asyncio.create_task(_mcp_usage_aggregate_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.mcp.usage.aggregate_interval = 0.01
            mock_factory.side_effect = RuntimeError("db down")

            task = asyncio.create_task(_mcp_usage_aggregate_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestBackgroundSweep:
    async def test_sweep_success_logs_message(self, caplog: pytest.LogCaptureFixture) -> None:
        async def sweep() -> str | None:
            return "did 3 things"

        task = asyncio.create_task(_background_sweep(0.01, "test-task", sweep))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert any("test-task: did 3 things" in r.message for r in caplog.records)

    async def test_sweep_returns_none_no_log(self, caplog: pytest.LogCaptureFixture) -> None:
        async def sweep() -> str | None:
            return None

        task = asyncio.create_task(_background_sweep(0.01, "test-task", sweep))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not any("test-task:" in r.message for r in caplog.records if r.levelname == "INFO")

    async def test_sweep_exception_logged_and_continues(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        call_count = 0

        async def sweep() -> str | None:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("boom")

        task = asyncio.create_task(_background_sweep(0.01, "test-task", sweep))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert call_count >= 2
        assert any("test-task sweep failed" in r.message for r in caplog.records)


class TestSweepFunctions:
    async def test_sweep_expired_tokens(self) -> None:
        with (
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch("openhands.ev2.auth.auth_service.AuthService") as mock_service_cls,
        ):
            mock_service = AsyncMock()
            mock_service.delete_expired_tokens.return_value = 5
            mock_service.aclose = AsyncMock()
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_expired_tokens()
            assert result is not None
            assert "5" in result
            mock_service.delete_expired_tokens.assert_awaited_once()
            mock_service.aclose.assert_awaited_once()

    async def test_sweep_expired_tokens_none(self) -> None:
        with (
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch("openhands.ev2.auth.auth_service.AuthService") as mock_service_cls,
        ):
            mock_service = AsyncMock()
            mock_service.delete_expired_tokens.return_value = 0
            mock_service.aclose = AsyncMock()
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_expired_tokens()
            assert result is None

    async def test_sweep_llm_partitions(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch("openhands.ev2.llm.llm_usage_service.LlmUsageService") as mock_service_cls,
        ):
            mock_cfg.return_value.llm.usage.preallocate_days = 3
            mock_cfg.return_value.llm.usage.retention_days = 30

            mock_service = AsyncMock()
            mock_service.ensure_partitions.return_value = (["p1", "p2"], ["old"])
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_llm_partitions()
            assert result is not None
            assert "2" in result and "1" in result

    async def test_sweep_llm_aggregate(self) -> None:
        with (
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch("openhands.ev2.llm.llm_usage_service.LlmUsageService") as mock_service_cls,
        ):
            mock_service = AsyncMock()
            mock_service.aggregate_behind_now.return_value = 10
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_llm_aggregate()
            assert result is not None
            assert "10" in result

    async def test_sweep_mcp_partitions(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch(
                "openhands.ev2.mcp_server_config.mcp_usage_service.McpUsageService"
            ) as mock_service_cls,
        ):
            mock_cfg.return_value.mcp.usage.preallocate_days = 3
            mock_cfg.return_value.mcp.usage.retention_days = 30

            mock_service = AsyncMock()
            mock_service.ensure_partitions.return_value = (["p1"], ["old", "older"])
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_mcp_partitions()
            assert result is not None
            assert "1" in result and "2" in result

    async def test_sweep_mcp_aggregate(self) -> None:
        with (
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch(
                "openhands.ev2.mcp_server_config.mcp_usage_service.McpUsageService"
            ) as mock_service_cls,
        ):
            mock_service = AsyncMock()
            mock_service.aggregate_behind_now.return_value = 0
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_mcp_aggregate()
            assert result is None

    async def test_sweep_sandbox_usage(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch(
                "openhands.ev2.sandbox.sandbox_usage_service.SandboxUsageService"
            ) as mock_service_cls,
        ):
            mock_sandbox_service = AsyncMock()
            mock_sandbox_service.list_sandboxes.return_value = [object(), object(), object()]
            mock_cfg.return_value.get_sandbox_service.return_value = mock_sandbox_service

            mock_service = AsyncMock()
            mock_service.record_usage.return_value = 3
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_sandbox_usage()
            assert result is not None
            assert "3" in result
            mock_service.record_usage.assert_awaited_once()

    async def test_sweep_sandbox_usage_none(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
            patch(
                "openhands.ev2.sandbox.sandbox_usage_service.SandboxUsageService"
            ) as mock_service_cls,
        ):
            mock_sandbox_service = AsyncMock()
            mock_sandbox_service.list_sandboxes.return_value = []
            mock_cfg.return_value.get_sandbox_service.return_value = mock_sandbox_service

            mock_service = AsyncMock()
            mock_service.record_usage.return_value = 0
            mock_service_cls.return_value = mock_service

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            result = await _sweep_sandbox_usage()
            assert result is None


class TestSandboxUsageLoop:
    async def test_interval_zero_returns_immediately(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.sandbox_usage_interval = 0
            await _sandbox_usage_loop()

    async def test_sweep_records_usage(self) -> None:
        with (
            patch("openhands.ev2.app.get_config") as mock_cfg,
            patch("openhands.ev2.app.get_session_factory") as mock_factory,
        ):
            mock_cfg.return_value.sandbox_usage_interval = 0.01
            mock_sandbox_service = AsyncMock()
            mock_sandbox_service.list_sandboxes.return_value = [object(), object()]
            mock_cfg.return_value.get_sandbox_service.return_value = mock_sandbox_service

            class FakeService:
                def __init__(self, session):
                    pass

                async def record_usage(self, sandboxes):
                    return len(list(sandboxes))

            session_cm = AsyncMock()
            session_cm.__aenter__ = AsyncMock(return_value=object())
            session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value.return_value = session_cm

            with patch(
                "openhands.ev2.sandbox.sandbox_usage_service.SandboxUsageService", FakeService
            ):
                task = asyncio.create_task(_sandbox_usage_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            mock_sandbox_service.list_sandboxes.assert_awaited()

    async def test_sweep_logs_exception_and_continues(self) -> None:
        with patch("openhands.ev2.app.get_config") as mock_cfg:
            mock_cfg.return_value.sandbox_usage_interval = 0.01
            mock_cfg.return_value.get_sandbox_service.side_effect = RuntimeError("no provider")

            task = asyncio.create_task(_sandbox_usage_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


class TestPartitionMessage:
    def test_both_created_and_dropped(self) -> None:
        msg = _partition_message(["p1"], ["p2"])
        assert msg is not None
        assert "created 1" in msg and "dropped 1" in msg

    def test_only_created(self) -> None:
        msg = _partition_message(["p1"], [])
        assert msg is not None
        assert "created" in msg
        assert "dropped" not in msg

    def test_only_dropped(self) -> None:
        msg = _partition_message([], ["p1"])
        assert msg is not None
        assert "dropped" in msg
        assert "created" not in msg

    def test_neither(self) -> None:
        msg = _partition_message([], [])
        assert msg is None


class TestLifespan:
    async def test_lifespan_starts_and_cancels_tasks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from fastapi import FastAPI

        from openhands.ev2.config import get_config

        get_config.cache_clear()
        monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
        monkeypatch.setenv("OHE_DB_CONFIG_HOST", "localhost")
        monkeypatch.setenv("OHE_DB_CONFIG_PORT", "5432")
        monkeypatch.setenv("OHE_DB_CONFIG_DB_NAME", "ohev")
        monkeypatch.setenv("OHE_DB_CONFIG_USERNAME", "ohev")
        monkeypatch.setenv("OHE_DB_CONFIG_PASSWORD", "ohev")
        monkeypatch.setenv("OHE_IDP_URL", "https://idp.example.com")
        monkeypatch.setenv("OHE_IDP_CLIENT_ID", "test-client")
        monkeypatch.setenv("OHE_IDP_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("OHE_BASE_URL", "http://test")
        monkeypatch.setenv("OHE_CLEANUP_INTERVAL", "0")
        monkeypatch.setenv("OHE_LLM_USAGE_PARTITION_INTERVAL", "0")
        monkeypatch.setenv("OHE_LLM_USAGE_AGGREGATE_INTERVAL", "0")
        monkeypatch.setenv("OHE_MCP_USAGE_PARTITION_INTERVAL", "0")
        monkeypatch.setenv("OHE_MCP_USAGE_AGGREGATE_INTERVAL", "0")
        monkeypatch.setenv("OHE_SANDBOX_USAGE_INTERVAL", "0")

        app = FastAPI()
        async with lifespan(app):
            await asyncio.sleep(0.01)
