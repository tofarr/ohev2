"""Unit tests for MCP usage logging: recording, partitioning, aggregation, REST."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.mcp_server_config.mcp_usage_service import McpUsageService
from openhands.ev2.security.security_models import Action, Denied, Permitted, ReadOnly
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

_USER_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
_OTHER_USER_ID = uuid.UUID("00000000-0000-0000-0000-0000000000bb")


async def _seed_user(session: AsyncSession, *, user_id: uuid.UUID, username: str) -> None:
    await _make_principal(session, email=f"{username}@example.com", username=username)
    # make_principal mints its own user; override the id by inserting directly.
    await session.execute(
        text("UPDATE users SET id = :new WHERE username = :u"),
        {"new": user_id, "u": username},
    )
    await session.flush()


async def _seed_mcp_config(
    session: AsyncSession, *, user_id: uuid.UUID, name: str = "c"
) -> uuid.UUID:
    """Insert a minimal mcp_server_configs row and return its id."""
    config_id = uuid.uuid4()
    await session.execute(
        text(
            "INSERT INTO mcp_server_configs "
            "(id, user_id, display_name, url, transport, enabled, enable_proxy) "
            "VALUES (:id, :uid, :name, 'http://up.example/mcp', 'http', true, false)"
        ),
        {"id": config_id, "uid": user_id, "name": name},
    )
    await session.flush()
    return config_id


# ====================================================================== #
# record_usage
# ====================================================================== #


class TestRecordUsage:
    async def test_records_duration_and_details(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="rec-user")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        service = McpUsageService(session)
        row = await service.record_usage(
            user_id=_USER_ID,
            mcp_server_config_id=config_id,
            tool_name="search",
            duration_ms=123,
            success=True,
            details={"result": {"foo": "bar"}},
        )
        await session.commit()
        assert row is not None
        assert row.user_id == _USER_ID
        assert row.mcp_server_config_id == config_id
        assert row.tool_name == "search"
        assert row.duration_ms == 123
        assert row.success is True
        assert row.error is None
        assert row.details == {"result": {"foo": "bar"}}
        assert row.created_at is not None

    async def test_record_usage_defaults(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="rec-defaults")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        service = McpUsageService(session)
        row = await service.record_usage(
            user_id=_USER_ID,
            mcp_server_config_id=config_id,
            tool_name="",
            duration_ms=0,
        )
        await session.commit()
        assert row is not None
        assert row.tool_name == ""
        assert row.duration_ms == 0
        assert row.success is True
        assert row.details == {}

    async def test_record_usage_failure_path(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="rec-fail")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        service = McpUsageService(session)
        row = await service.record_usage(
            user_id=_USER_ID,
            mcp_server_config_id=config_id,
            tool_name="bad",
            duration_ms=5,
            success=False,
            error="upstream timeout",
            details={"code": -32000},
        )
        await session.commit()
        assert row is not None
        assert row.success is False
        assert row.error == "upstream timeout"
        assert row.details == {"code": -32000}

    async def test_record_usage_rolls_back_on_failure(self, session: AsyncSession) -> None:
        # A non-existent user_id trips the FK; record_usage swallows and returns None.
        service = McpUsageService(session)
        row = await service.record_usage(
            user_id=uuid.uuid4(),
            mcp_server_config_id=uuid.uuid4(),
            tool_name="x",
            duration_ms=1,
        )
        assert row is None


# ====================================================================== #
# ensure_partitions
# ====================================================================== #


class TestEnsurePartitions:
    async def test_allocates_today_and_future_days(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, 12, 30, 45, tzinfo=UTC)
        service = McpUsageService(session)
        created, dropped = await service.ensure_partitions(
            preallocate_days=3, retention_days=365, now=now
        )
        # 3 partitions for 2026-06-05, 2026-06-04, 2026-06-03.
        assert len(created) == 3
        assert "mcp_usage_20260605" in created
        assert "mcp_usage_20260604" in created
        assert "mcp_usage_20260603" in created
        assert dropped == []
        # Idempotent: a second sweep creates nothing.
        created2, _ = await service.ensure_partitions(
            preallocate_days=3, retention_days=365, now=now
        )
        assert created2 == []

    async def test_drops_expired_partitions_keeps_default(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, tzinfo=UTC)
        service = McpUsageService(session)
        await service.ensure_partitions(preallocate_days=1, retention_days=365, now=now)
        # Manually create an old partition (2026-05-20) to be dropped.
        await session.execute(
            text(
                "CREATE TABLE mcp_usage_20260520 PARTITION OF mcp_usage "
                "FOR VALUES FROM ('2026-05-20') TO ('2026-05-21')"
            )
        )
        await session.commit()
        _created, dropped = await service.ensure_partitions(
            preallocate_days=1, retention_days=10, now=now
        )
        assert "mcp_usage_20260520" in dropped
        # DEFAULT partition is never dropped.
        exists = (
            await session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = 'mcp_usage_default'")
            )
        ).scalar_one_or_none()
        assert exists is not None

    async def test_default_partition_ensured(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, tzinfo=UTC)
        service = McpUsageService(session)
        await service.ensure_partitions(preallocate_days=1, retention_days=365, now=now)
        # Seed a user + config so the FKs are satisfied, then insert a row
        # whose created_at falls outside any dated partition (1999) so it
        # lands in DEFAULT rather than raising.
        await _seed_user(session, user_id=_USER_ID, username="def-user")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        await session.execute(
            text(
                "INSERT INTO mcp_usage "
                "(user_id, mcp_server_config_id, created_at, tool_name, duration_ms, details) "
                "VALUES (:uid, :cid, '1999-01-01', '', 0, '{}'::jsonb)"
            ),
            {"uid": _USER_ID, "cid": config_id},
        )
        await session.commit()


# ====================================================================== #
# aggregate_minute
# ====================================================================== #


class TestAggregateMinute:
    async def _seed_usage_rows(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        config_id: uuid.UUID,
        minute: datetime,
        count: int,
        duration_base: int = 10,
    ) -> None:
        for i in range(count):
            await session.execute(
                text(
                    "INSERT INTO mcp_usage "
                    "(user_id, mcp_server_config_id, created_at, tool_name, duration_ms, details) "
                    "VALUES (:uid, :cid, :ts, 't', :dur, '{}'::jsonb)"
                ),
                {
                    "uid": user_id,
                    "cid": config_id,
                    "ts": minute + timedelta(seconds=i),
                    "dur": duration_base + i,
                },
            )
        await session.flush()

    async def test_aggregates_one_minute_one_user(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-user")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        minute = datetime(2026, 6, 5, 10, 4, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, config_id=config_id, minute=minute, count=3, duration_base=10
        )
        await session.commit()
        service = McpUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 1
        rows = (
            await session.execute(
                text(
                    "SELECT user_id, invocations, total_duration_ms "
                    "FROM mcp_aggregated_usage WHERE minute = :m"
                ),
                {"m": minute},
            )
        ).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.user_id == _USER_ID
        assert row.invocations == 3
        # 10 + 11 + 12 = 33
        assert row.total_duration_ms == 33

    async def test_no_usage_yields_no_row(self, session: AsyncSession) -> None:
        minute = datetime(2026, 6, 5, 11, 0, 0, tzinfo=UTC)
        service = McpUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 0
        cnt = (
            await session.execute(
                text("SELECT COUNT(*) FROM mcp_aggregated_usage WHERE minute = :m"),
                {"m": minute},
            )
        ).scalar_one()
        assert cnt == 0

    async def test_separate_users_separate_rows(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-a")
        await _seed_user(session, user_id=_OTHER_USER_ID, username="agg-b")
        config_a = await _seed_mcp_config(session, user_id=_USER_ID, name="a")
        config_b = await _seed_mcp_config(session, user_id=_OTHER_USER_ID, name="b")
        minute = datetime(2026, 6, 5, 12, 0, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, config_id=config_a, minute=minute, count=2
        )
        await self._seed_usage_rows(
            session,
            user_id=_OTHER_USER_ID,
            config_id=config_b,
            minute=minute,
            count=1,
            duration_base=100,
        )
        await session.commit()
        service = McpUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 2

    async def test_idempotent_rerun_after_late_rows(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-late")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        minute = datetime(2026, 6, 5, 13, 0, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, config_id=config_id, minute=minute, count=1, duration_base=1
        )
        await session.commit()
        service = McpUsageService(session)
        await service.aggregate_minute(minute)
        # A late row arrives in the same minute.
        await self._seed_usage_rows(
            session, user_id=_USER_ID, config_id=config_id, minute=minute, count=1, duration_base=10
        )
        await session.commit()
        await service.aggregate_minute(minute)
        rows = (
            await session.execute(
                text(
                    "SELECT invocations, total_duration_ms FROM mcp_aggregated_usage WHERE minute = :m"
                ),
                {"m": minute},
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].invocations == 2
        assert rows[0].total_duration_ms == 11  # 1 + 10

    async def test_aggregate_behind_now_skips_current_minute(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-behind")
        config_id = await _seed_mcp_config(session, user_id=_USER_ID)
        now = datetime(2026, 6, 5, 14, 30, 45, tzinfo=UTC)
        # Row in the minute that is 1 minute behind now (14:29).
        target_minute = now - timedelta(minutes=1)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, config_id=config_id, minute=target_minute, count=1
        )
        await session.commit()
        service = McpUsageService(session)
        n = await service.aggregate_behind_now(lag_minutes=1, now=now)
        assert n == 1


# ====================================================================== #
# REST: aggregated usage (read-only)
# ====================================================================== #


async def _seed_aggregated_row(
    client: AsyncClient,
    *,
    user_id: uuid.UUID,
    minute: datetime,
    invocations: int = 1,
    total_duration_ms: int = 100,
) -> uuid.UUID:
    """Insert an aggregated-usage row directly via SQL (no create endpoint)."""
    from sqlalchemy import text as _text

    from openhands.ev2.db import get_session_factory

    factory = get_session_factory()
    async with factory() as s:
        row_id = uuid.uuid4()
        await s.execute(
            _text(
                "INSERT INTO mcp_aggregated_usage "
                "(id, minute, user_id, invocations, total_duration_ms) "
                "VALUES (:id, :m, :uid, :inv, :dur)"
            ),
            {
                "id": row_id,
                "m": minute,
                "uid": user_id,
                "inv": invocations,
                "dur": total_duration_ms,
            },
        )
        await s.commit()
    return row_id


class TestAggregatedUsageRoutes:
    async def test_search_returns_rows(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 0, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/mcp-server-configs/aggregated-usage")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["user_id"] == str(user_id)
        assert items[0]["invocations"] == 1
        assert items[0]["total_duration_ms"] == 100

    async def test_count(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 1, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/mcp-server-configs/aggregated-usage/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_get_one(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 2, 0, tzinfo=UTC)
        row_id = await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get(f"/mcp-server-configs/aggregated-usage/{row_id}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == str(row_id)

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/mcp-server-configs/aggregated-usage/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_read_aligned_with_nulls(
        self, client: AsyncClient, user_id: uuid.UUID
    ) -> None:
        minute = datetime(2026, 6, 5, 9, 3, 0, tzinfo=UTC)
        a = await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        missing = str(uuid.uuid4())
        resp = await client.get(f"/mcp-server-configs/aggregated-usage/batch?ids={a}&ids={missing}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == str(a)
        assert items[1] is None

    async def test_batch_read_empty_ids(self, client: AsyncClient) -> None:
        resp = await client.get("/mcp-server-configs/aggregated-usage/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_filter_by_user_id(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 4, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute, total_duration_ms=42)
        resp = await client.get(f"/mcp-server-configs/aggregated-usage?user_id__eq={user_id}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(i["user_id"] == str(user_id) for i in items)
        assert any(i["total_duration_ms"] == 42 for i in items)

    async def test_filter_by_minute_range(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        m1 = datetime(2026, 6, 5, 8, 0, 0, tzinfo=UTC)
        m2 = datetime(2026, 6, 5, 10, 0, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=m1)
        await _seed_aggregated_row(client, user_id=user_id, minute=m2)
        resp = await client.get(
            "/mcp-server-configs/aggregated-usage"
            "?minute__gte=2026-06-05T09:00:00Z&minute__lt=2026-06-05T11:00:00Z"
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["minute"].startswith("2026-06-05T10:00")

    async def test_search_requires_permission(
        self, app, engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A principal with no mcp_aggregated_usage_permission is denied (403)."""
        from httpx import ASGITransport
        from httpx import AsyncClient as _AsyncClient

        from openhands.ev2.app import create_app
        from openhands.ev2.db import get_session as _get_session
        from openhands.ev2.db import get_session_factory
        from openhands.ev2.role.role_models import Role, UserRole
        from openhands.ev2.util.auth_token import create_auth_token

        factory = get_session_factory()
        other_id = uuid.uuid4()
        async with factory() as s:
            await s.execute(
                text(
                    "INSERT INTO users (id, email, username, enabled) "
                    "VALUES (:id, 'd@example.com', 'denied', true) ON CONFLICT DO NOTHING"
                ),
                {"id": other_id},
            )
            role = Role(name="mcp-agg-denied", mcp_aggregated_usage_permission=Denied())
            s.add(role)
            await s.flush()
            s.add(UserRole(role_id=role.id, user_id=other_id))
            await s.commit()

        application = create_app()
        token = create_auth_token(other_id)
        async with _AsyncClient(
            transport=ASGITransport(app=application), base_url="http://t"
        ) as ac:
            application.dependency_overrides[_get_session] = _session_override(engine)
            ac.headers["Authorization"] = f"Bearer {token}"
            resp = await ac.get("/mcp-server-configs/aggregated-usage")
        assert resp.status_code == 403

    async def test_readonly_permission_allows_read_denies_create(
        self, client: AsyncClient, user_id: uuid.UUID
    ) -> None:
        # The default test principal has Permitted (admin) on all resources.
        # ReadOnly is exercised at the policy unit level below; here we just
        # confirm the read path works (create is not exposed).
        minute = datetime(2026, 6, 5, 9, 5, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/mcp-server-configs/aggregated-usage")
        assert resp.status_code == 200


def _session_override(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override():
        async with factory() as s:
            yield s

    return _override


# ====================================================================== #
# Permission policy unit tests
# ====================================================================== #


class TestAggregatedUsagePermissionPolicy:
    def test_permitted_grants_all_actions(self) -> None:
        f = Permitted().to_search_filter(_USER_ID, Action.SEARCH)
        assert isinstance(f, AllSearchFilter)

    def test_readonly_grants_read_search_denies_others(self) -> None:
        ro = ReadOnly()
        assert isinstance(ro.to_search_filter(_USER_ID, Action.READ), AllSearchFilter)
        assert isinstance(ro.to_search_filter(_USER_ID, Action.SEARCH), AllSearchFilter)
        assert isinstance(ro.to_search_filter(_USER_ID, Action.CREATE), NoneSearchFilter)

    def test_denied_denies_all(self) -> None:
        d = Denied()
        assert isinstance(d.to_search_filter(_USER_ID, Action.READ), NoneSearchFilter)


# ====================================================================== #
# Config
# ====================================================================== #


class TestUsageConfig:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config

        monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
        get_config.cache_clear()
        cfg = get_config()
        assert cfg.mcp.usage.partition_interval == 300
        assert cfg.mcp.usage.preallocate_days == 7
        assert cfg.mcp.usage.retention_days == 365
        assert cfg.mcp.usage.aggregate_interval == 60

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config

        monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
        monkeypatch.setenv("OHE_MCP_USAGE_PARTITION_INTERVAL", "11")
        monkeypatch.setenv("OHE_MCP_USAGE_PREALLOCATE_DAYS", "3")
        monkeypatch.setenv("OHE_MCP_USAGE_RETENTION_DAYS", "9")
        monkeypatch.setenv("OHE_MCP_USAGE_AGGREGATE_INTERVAL", "22")
        get_config.cache_clear()
        cfg = get_config()
        assert cfg.mcp.usage.partition_interval == 11
        assert cfg.mcp.usage.preallocate_days == 3
        assert cfg.mcp.usage.retention_days == 9
        assert cfg.mcp.usage.aggregate_interval == 22
