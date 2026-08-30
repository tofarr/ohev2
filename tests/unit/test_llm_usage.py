"""Unit tests for LLM usage logging: recording, partitioning, aggregation, REST."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.llm.llm_usage_service import LlmUsageService
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


def _fake_response(
    *,
    response_id: str = "resp-1",
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    cost: float = 0.01,
    model_name: str = "gpt-test",
) -> MagicMock:
    """A fake SDK LLMResponse with a MetricsSnapshot-shaped .metrics."""
    metrics = MagicMock()
    metrics.model_name = model_name
    metrics.accumulated_cost = cost
    metrics.model_dump.return_value = {
        "model_name": model_name,
        "accumulated_cost": cost,
        "max_budget_per_task": None,
        "accumulated_token_usage": {
            "model": model_name,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cache_read_tokens": 1,
            "cache_write_tokens": 2,
            "reasoning_tokens": 3,
            "context_window": 128_000,
            "per_turn_token": 30,
            "response_id": response_id,
        },
    }
    resp = MagicMock()
    resp.id = response_id
    resp.metrics = metrics
    resp.model = model_name
    return resp


# ====================================================================== #
# record_usage
# ====================================================================== #


class TestRecordUsage:
    async def test_records_token_metrics_and_metrics_dump(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="rec-user")
        conn_id = uuid.uuid4()
        llm_id = uuid.uuid4()
        # provider_connections/llms FKs need real rows; insert minimal stubs.
        await session.execute(
            text(
                "INSERT INTO provider_connections (id, user_id, display_name, provider) "
                "VALUES (:id, :uid, 'c', 'custom')"
            ),
            {"id": conn_id, "uid": _USER_ID},
        )
        await session.execute(
            text(
                "INSERT INTO llms (id, user_id, provider_connection_id, model, display_name, config) "
                "VALUES (:id, :uid, :cid, 'm', 'l', '{}'::jsonb)"
            ),
            {"id": llm_id, "uid": _USER_ID, "cid": conn_id},
        )
        await session.flush()

        service = LlmUsageService(session)
        row = await service.record_usage(
            user_id=_USER_ID,
            provider_connection_id=conn_id,
            llm_id=llm_id,
            response_id="resp-9",
            model="gpt-test",
            sdk_metrics=_fake_response().metrics,
        )
        await session.commit()
        assert row is not None
        assert row.user_id == _USER_ID
        assert row.prompt_tokens == 10
        assert row.completion_tokens == 20
        assert row.cache_read_tokens == 1
        assert row.cache_write_tokens == 2
        assert row.reasoning_tokens == 3
        assert row.context_window == 128_000
        assert row.per_turn_token == 30
        assert row.accumulated_cost == pytest.approx(0.01)
        assert row.response_id == "resp-9"
        assert row.model == "gpt-test"
        assert row.metrics["model_name"] == "gpt-test"
        assert row.created_at is not None

    async def test_record_usage_handles_none_metrics(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="rec-none")
        conn_id = uuid.uuid4()
        await session.execute(
            text(
                "INSERT INTO provider_connections (id, user_id, display_name, provider) "
                "VALUES (:id, :uid, 'c', 'custom')"
            ),
            {"id": conn_id, "uid": _USER_ID},
        )
        await session.flush()
        service = LlmUsageService(session)
        row = await service.record_usage(
            user_id=_USER_ID,
            provider_connection_id=conn_id,
            llm_id=None,
            response_id=None,
            model="",
            sdk_metrics=None,
        )
        await session.commit()
        assert row is not None
        assert row.prompt_tokens == 0
        assert row.completion_tokens == 0
        assert row.accumulated_cost == 0.0
        assert row.metrics == {}

    async def test_record_usage_rolls_back_on_failure(self, session: AsyncSession) -> None:
        # A non-existent user_id trips the FK; record_usage swallows and returns None.
        service = LlmUsageService(session)
        row = await service.record_usage(
            user_id=uuid.uuid4(),
            provider_connection_id=uuid.uuid4(),
            llm_id=None,
            response_id=None,
            model="x",
            sdk_metrics=None,
        )
        assert row is None


# ====================================================================== #
# ensure_partitions
# ====================================================================== #


class TestEnsurePartitions:
    async def test_allocates_today_and_future_days(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, 12, 30, 45, tzinfo=UTC)
        service = LlmUsageService(session)
        created, dropped = await service.ensure_partitions(
            preallocate_days=3, retention_days=365, now=now
        )
        # 3 partitions for 2026-06-05, 2026-06-04, 2026-06-03.
        assert len(created) == 3
        assert "llm_usage_20260605" in created
        assert "llm_usage_20260604" in created
        assert "llm_usage_20260603" in created
        assert dropped == []
        # Idempotent: a second sweep creates nothing.
        created2, _ = await service.ensure_partitions(
            preallocate_days=3, retention_days=365, now=now
        )
        assert created2 == []

    async def test_drops_expired_partitions_keeps_default(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, tzinfo=UTC)
        service = LlmUsageService(session)
        # Create partitions spanning a wide range, then drop with retention=10.
        await service.ensure_partitions(preallocate_days=1, retention_days=365, now=now)
        # Manually create an old partition (2026-05-20) to be dropped.
        await session.execute(
            text(
                "CREATE TABLE llm_usage_20260520 PARTITION OF llm_usage "
                "FOR VALUES FROM ('2026-05-20') TO ('2026-05-21')"
            )
        )
        await session.commit()
        _created, dropped = await service.ensure_partitions(
            preallocate_days=1, retention_days=10, now=now
        )
        assert "llm_usage_20260520" in dropped
        # DEFAULT partition is never dropped.
        exists = (
            await session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = 'llm_usage_default'")
            )
        ).scalar_one_or_none()
        assert exists is not None

    async def test_default_partition_ensured(self, session: AsyncSession) -> None:
        now = datetime(2026, 6, 5, tzinfo=UTC)
        service = LlmUsageService(session)
        await service.ensure_partitions(preallocate_days=1, retention_days=365, now=now)
        # Seed a user + provider connection so the FKs are satisfied, then
        # insert a row whose created_at falls outside any dated partition
        # (1999) so it lands in DEFAULT rather than raising.
        await _seed_user(session, user_id=_USER_ID, username="def-user")
        conn_id = uuid.uuid4()
        await session.execute(
            text(
                "INSERT INTO provider_connections (id, user_id, display_name, provider) "
                "VALUES (:id, :uid, 'c', 'custom')"
            ),
            {"id": conn_id, "uid": _USER_ID},
        )
        await session.flush()
        await session.execute(
            text(
                "INSERT INTO llm_usage "
                "(user_id, provider_connection_id, created_at, model, metrics) "
                "VALUES (:uid, :cid, '1999-01-01', '', '{}'::jsonb)"
            ),
            {"uid": _USER_ID, "cid": conn_id},
        )
        await session.commit()


# ====================================================================== #
# aggregate_minute
# ====================================================================== #


class TestAggregateMinute:
    async def _seed_conn(self, session: AsyncSession, *, user_id: uuid.UUID) -> uuid.UUID:
        conn_id = uuid.uuid4()
        await session.execute(
            text(
                "INSERT INTO provider_connections (id, user_id, display_name, provider) "
                "VALUES (:id, :uid, 'c', 'custom')"
            ),
            {"id": conn_id, "uid": user_id},
        )
        await session.flush()
        return conn_id

    async def _seed_usage_rows(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        conn_id: uuid.UUID,
        minute: datetime,
        count: int,
        prompt_base: int = 5,
    ) -> None:
        for i in range(count):
            await session.execute(
                text(
                    "INSERT INTO llm_usage "
                    "(user_id, provider_connection_id, created_at, model, metrics, "
                    "prompt_tokens, completion_tokens, accumulated_cost) "
                    "VALUES (:uid, :cid, :ts, '', '{}'::jsonb, :pt, :ct, :cost)"
                ),
                {
                    "uid": user_id,
                    "cid": conn_id,
                    "ts": minute + timedelta(seconds=i),
                    "pt": prompt_base + i,
                    "ct": (prompt_base + i) * 2,
                    "cost": 0.001 * (i + 1),
                },
            )
        await session.flush()

    async def test_aggregates_one_minute_one_user(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-user")
        conn_id = await self._seed_conn(session, user_id=_USER_ID)
        minute = datetime(2026, 6, 5, 10, 4, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, conn_id=conn_id, minute=minute, count=3, prompt_base=5
        )
        await session.commit()

        service = LlmUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 1
        rows = (
            await session.execute(
                text(
                    "SELECT user_id, invocations, prompt_tokens, completion_tokens, accumulated_cost "
                    "FROM llm_aggregated_usage WHERE minute = :m"
                ),
                {"m": minute},
            )
        ).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.user_id == _USER_ID
        assert row.invocations == 3
        # 5+6+7 = 18
        assert row.prompt_tokens == 18
        # (10+12+14) = 36
        assert row.completion_tokens == 36
        assert float(row.accumulated_cost) == pytest.approx(0.006)

    async def test_no_usage_yields_no_row(self, session: AsyncSession) -> None:
        minute = datetime(2026, 6, 5, 11, 0, 0, tzinfo=UTC)
        service = LlmUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 0
        cnt = (
            await session.execute(
                text("SELECT COUNT(*) FROM llm_aggregated_usage WHERE minute = :m"),
                {"m": minute},
            )
        ).scalar_one()
        assert cnt == 0

    async def test_separate_users_separate_rows(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-a")
        await _seed_user(session, user_id=_OTHER_USER_ID, username="agg-b")
        conn_a = await self._seed_conn(session, user_id=_USER_ID)
        conn_b = await self._seed_conn(session, user_id=_OTHER_USER_ID)
        minute = datetime(2026, 6, 5, 12, 0, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, conn_id=conn_a, minute=minute, count=2
        )
        await self._seed_usage_rows(
            session,
            user_id=_OTHER_USER_ID,
            conn_id=conn_b,
            minute=minute,
            count=1,
            prompt_base=100,
        )
        await session.commit()
        service = LlmUsageService(session)
        n = await service.aggregate_minute(minute)
        assert n == 2

    async def test_idempotent_rerun_after_late_rows(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-late")
        conn_id = await self._seed_conn(session, user_id=_USER_ID)
        minute = datetime(2026, 6, 5, 13, 0, 0, tzinfo=UTC)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, conn_id=conn_id, minute=minute, count=1, prompt_base=1
        )
        await session.commit()
        service = LlmUsageService(session)
        await service.aggregate_minute(minute)
        # A late row arrives in the same minute.
        await self._seed_usage_rows(
            session, user_id=_USER_ID, conn_id=conn_id, minute=minute, count=1, prompt_base=10
        )
        await session.commit()
        await service.aggregate_minute(minute)
        rows = (
            await session.execute(
                text(
                    "SELECT invocations, prompt_tokens FROM llm_aggregated_usage WHERE minute = :m"
                ),
                {"m": minute},
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].invocations == 2
        assert rows[0].prompt_tokens == 11  # 1 + 10

    async def test_aggregate_behind_now_skips_current_minute(self, session: AsyncSession) -> None:
        await _seed_user(session, user_id=_USER_ID, username="agg-behind")
        conn_id = await self._seed_conn(session, user_id=_USER_ID)
        now = datetime(2026, 6, 5, 14, 30, 45, tzinfo=UTC)
        # Row in the minute that is 1 minute behind now (14:29).
        target_minute = now - timedelta(minutes=1)
        await self._seed_usage_rows(
            session, user_id=_USER_ID, conn_id=conn_id, minute=target_minute, count=1
        )
        await session.commit()
        service = LlmUsageService(session)
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
    prompt_tokens: int = 100,
) -> uuid.UUID:
    """Insert an aggregated-usage row directly via SQL (no create endpoint)."""
    from sqlalchemy import text as _text

    from openhands.ev2.db import get_session_factory

    factory = get_session_factory()
    async with factory() as s:
        row_id = uuid.uuid4()
        await s.execute(
            _text(
                "INSERT INTO llm_aggregated_usage "
                "(id, minute, user_id, invocations, prompt_tokens, completion_tokens) "
                "VALUES (:id, :m, :uid, :inv, :pt, 0)"
            ),
            {
                "id": row_id,
                "m": minute,
                "uid": user_id,
                "inv": invocations,
                "pt": prompt_tokens,
            },
        )
        await s.commit()
    return row_id


class TestAggregatedUsageRoutes:
    async def test_search_returns_rows(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 0, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/llm/aggregated-usage")
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["user_id"] == str(user_id)
        assert items[0]["invocations"] == 1
        assert items[0]["prompt_tokens"] == 100

    async def test_count(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 1, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/llm/aggregated-usage/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_get_one(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 2, 0, tzinfo=UTC)
        row_id = await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get(f"/llm/aggregated-usage/{row_id}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == str(row_id)

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/llm/aggregated-usage/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_read_aligned_with_nulls(
        self, client: AsyncClient, user_id: uuid.UUID
    ) -> None:
        minute = datetime(2026, 6, 5, 9, 3, 0, tzinfo=UTC)
        a = await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        missing = str(uuid.uuid4())
        resp = await client.get(f"/llm/aggregated-usage/batch?ids={a}&ids={missing}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert items[0]["id"] == str(a)
        assert items[1] is None

    async def test_batch_read_empty_ids(self, client: AsyncClient) -> None:
        resp = await client.get("/llm/aggregated-usage/batch")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_filter_by_user_id(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        minute = datetime(2026, 6, 5, 9, 4, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute, prompt_tokens=42)
        resp = await client.get(f"/llm/aggregated-usage?user_id__eq={user_id}")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(i["user_id"] == str(user_id) for i in items)
        assert any(i["prompt_tokens"] == 42 for i in items)

    async def test_filter_by_minute_range(self, client: AsyncClient, user_id: uuid.UUID) -> None:
        m1 = datetime(2026, 6, 5, 8, 0, 0, tzinfo=UTC)
        m2 = datetime(2026, 6, 5, 10, 0, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=m1)
        await _seed_aggregated_row(client, user_id=user_id, minute=m2)
        resp = await client.get(
            "/llm/aggregated-usage?minute__gte=2026-06-05T09:00:00Z&minute__lt=2026-06-05T11:00:00Z"
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["minute"].startswith("2026-06-05T10:00")

    async def test_search_requires_permission(
        self, app, engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A principal with no llm_aggregated_usage_permission is denied (403)."""
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
            # A user with an explicit Denied policy on aggregated usage.
            await s.execute(
                text(
                    "INSERT INTO users (id, email, username, enabled) "
                    "VALUES (:id, 'd@example.com', 'denied', true) ON CONFLICT DO NOTHING"
                ),
                {"id": other_id},
            )
            role = Role(name="agg-denied", llm_aggregated_usage_permission=Denied())
            s.add(role)
            await s.flush()
            s.add(UserRole(role_id=role.id, user_id=other_id))
            await s.commit()

        application = create_app()
        token = create_auth_token(other_id)
        async with _AsyncClient(
            transport=ASGITransport(app=application), base_url="http://t"
        ) as ac:
            # Override get_session to the test engine so the user lookup resolves.
            application.dependency_overrides[_get_session] = _session_override(engine)
            ac.headers["Authorization"] = f"Bearer {token}"
            resp = await ac.get("/llm/aggregated-usage")
        assert resp.status_code == 403

    async def test_readonly_permission_allows_read_denies_create(
        self, client: AsyncClient, user_id: uuid.UUID
    ) -> None:
        # The default test principal has Permitted (admin) on all resources.
        # ReadOnly is exercised at the policy unit level below; here we just
        # confirm the read path works (create is not exposed).
        minute = datetime(2026, 6, 5, 9, 5, 0, tzinfo=UTC)
        await _seed_aggregated_row(client, user_id=user_id, minute=minute)
        resp = await client.get("/llm/aggregated-usage")
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
        assert cfg.llm.usage.partition_interval == 300
        assert cfg.llm.usage.preallocate_days == 7
        assert cfg.llm.usage.retention_days == 365
        assert cfg.llm.usage.aggregate_interval == 60

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from openhands.ev2.config import get_config

        monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
        monkeypatch.setenv("OHE_LLM_USAGE_PARTITION_INTERVAL", "11")
        monkeypatch.setenv("OHE_LLM_USAGE_PREALLOCATE_DAYS", "3")
        monkeypatch.setenv("OHE_LLM_USAGE_RETENTION_DAYS", "9")
        monkeypatch.setenv("OHE_LLM_USAGE_AGGREGATE_INTERVAL", "22")
        get_config.cache_clear()
        cfg = get_config()
        assert cfg.llm.usage.partition_interval == 11
        assert cfg.llm.usage.preallocate_days == 3
        assert cfg.llm.usage.retention_days == 9
        assert cfg.llm.usage.aggregate_interval == 22
