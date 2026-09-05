"""Tests for app.py — background lifespan loops and app construction."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from openhands.ev2.app import (
    _cleanup_loop,
    _llm_usage_aggregate_loop,
    _llm_usage_partition_loop,
    _mcp_usage_aggregate_loop,
    _mcp_usage_partition_loop,
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

        app = FastAPI()
        async with lifespan(app):
            await asyncio.sleep(0.01)
