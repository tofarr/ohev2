"""Service layer for proxied MCP tool usage logging.

Three concerns, each a small single-purpose method (mirrors
:mod:`openhands.ev2.llm.llm_usage_service`):

* :meth:`McpUsageService.record_usage` — append a raw :class:`McpUsage` row
  after a proxied MCP ``tools/call``. Called from the MCP proxy endpoint;
  never raises into the response path (the caller has already returned the
  upstream response), so a logging failure is swallowed and logged rather than
  failing the request.
* :meth:`McpUsageService.ensure_partitions` — allocate future daily partitions
  of the range-partitioned ``mcp_usage`` table and drop expired ones. Driven by
  the background partition-manager loop.
* :meth:`McpUsageService.aggregate_minute` — roll one finished UTC minute of
  ``mcp_usage`` into ``mcp_aggregated_usage`` (upserting per-user sums +
  an invocation count). Driven by the background aggregator loop, which always
  processes the minute that ended at least one minute before wall-clock time so
  a finished minute is never partially aggregated.

The raw ``mcp_usage`` table is not exposed over REST; the read-only
``mcp_aggregated_usage`` projection is served by
:mod:`openhands.ev2.mcp_server_config.mcp_server_config_router`.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.mcp_server_config.mcp_usage_models import McpUsage

logger = logging.getLogger(__name__)

# Raw metric columns on ``mcp_usage`` rolled into the aggregated projection,
# mapped to their aggregated-column names. Kept in one place so the aggregator
# SQL and the record builder stay in sync.
_AGGREGATED_METRIC_COLUMNS: tuple[tuple[str, str], ...] = (("duration_ms", "total_duration_ms"),)
_AGGREGATED_COUNT_COLUMN = "invocations"


def _partition_name(day: datetime) -> str:
    """The daily partition table name for *day* (a UTC date)."""
    return f"mcp_usage_{day.strftime('%Y%m%d')}"


def _day_bounds(day: datetime) -> tuple[str, str]:
    """The ``[from, to)`` DATE bounds for the *day* partition (ISO strings)."""
    start = day.date().isoformat()
    end = (day + timedelta(days=1)).date().isoformat()
    return start, end


class McpUsageService:
    """Append raw usage rows, manage daily partitions, and roll aggregations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    async def record_usage(
        self,
        *,
        user_id: uuid.UUID,
        mcp_server_config_id: uuid.UUID,
        tool_name: str,
        duration_ms: int,
        success: bool = True,
        error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> McpUsage | None:
        """Append a raw usage row for one proxied MCP tool invocation.

        Returns the inserted row, or ``None`` when the insert failed (a missing
        partition for the current day is the likely cause — the partition
        manager should have allocated it). The caller must not let a failure
        here surface to the user; the proxied response has already succeeded.
        """
        row = McpUsage(
            user_id=user_id,
            mcp_server_config_id=mcp_server_config_id,
            tool_name=tool_name,
            duration_ms=duration_ms,
            success=success,
            error=error,
            details=details or {},
        )
        try:
            self._session.add(row)
            await self._session.flush()
            return row
        except Exception:
            await self._session.rollback()
            logger.exception("failed to record mcp usage row")
            return None

    # ------------------------------------------------------------------ #
    # Partition management
    # ------------------------------------------------------------------ #

    async def ensure_partitions(
        self,
        *,
        preallocate_days: int,
        retention_days: int,
        now: datetime | None = None,
    ) -> tuple[list[str], list[str]]:
        """Allocate future daily partitions and drop expired ones.

        Returns ``(created, dropped)`` — the names of partitions created and
        dropped this sweep. Idempotent: a partition that already exists is
        skipped (``CREATE TABLE IF NOT EXISTS``). A ``DEFAULT`` partition is
        ensured once so inserts never fail if the manager falls behind; rows
        landing there are picked up on the next sweep's allocations only if
        their day is still within the preallocation window (otherwise they
        stay in DEFAULT until retention drops the day).

        *now* defaults to the current UTC time; pass it for deterministic tests.
        """
        now = now or datetime.now(UTC)
        created: list[str] = []
        # Allocate today + the next ``preallocate_days - 1`` days.
        for offset in range(preallocate_days):
            day = (now - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            name = await self._ensure_partition(day)
            if name is not None:
                created.append(name)
        # Ensure a DEFAULT partition so inserts never fail when the manager
        # falls behind (rows there are queryable until their day is dropped).
        await self._session.execute(
            text("CREATE TABLE IF NOT EXISTS mcp_usage_default PARTITION OF mcp_usage DEFAULT")
        )
        dropped = await self._drop_expired_partitions(retention_days, now)
        await self._session.commit()
        return created, dropped

    async def _ensure_partition(self, day: datetime) -> str | None:
        """Create the daily partition for *day* if absent; return its name or None."""
        name = _partition_name(day)
        start, end = _day_bounds(day)
        # pg_class check avoids a CREATE that would raise on an existing
        # partition (IF NOT EXISTS on PARTITION OF is supported on PG 15+,
        # but the explicit check keeps this robust across versions and makes
        # the "created vs skipped" distinction explicit).
        exists = (
            await self._session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = :n"), {"n": name}
            )
        ).scalar_one_or_none()
        if exists is not None:
            return None
        await self._session.execute(
            text(
                f"CREATE TABLE {name} PARTITION OF mcp_usage "
                f"FOR VALUES FROM ('{start}') TO ('{end}')"
            )
        )
        return name

    async def _drop_expired_partitions(self, retention_days: int, now: datetime) -> list[str]:
        """Drop partitions older than ``retention_days``. Never drops DEFAULT."""
        cutoff = (now - timedelta(days=retention_days)).date()
        rows = (
            await self._session.execute(
                text(
                    "SELECT inhrelid::regclass::text AS name FROM pg_inherits "
                    "WHERE inhparent = 'mcp_usage'::regclass "
                    "AND inhrelid::regclass::text LIKE 'mcp_usage_%'"
                )
            )
        ).all()
        dropped: list[str] = []
        for row in rows:
            name = row[0]
            # Parse the YYYYMMDD suffix off the partition name.
            suffix = name.rsplit("_", 1)[-1] if "_" in name else ""
            try:
                day = datetime.strptime(suffix, "%Y%m%d").date()
            except ValueError:
                continue  # not a dated partition (e.g. mcp_usage_default is filtered by the LIKE)
            if day < cutoff:
                await self._session.execute(text(f"DROP TABLE IF EXISTS {name}"))
                dropped.append(name)
        return dropped

    # ------------------------------------------------------------------ #
    # Aggregation
    # ------------------------------------------------------------------ #

    async def aggregate_minute(self, minute: datetime) -> int:
        """Roll one UTC minute of raw usage into the aggregated projection.

        *minute* is the UTC minute to aggregate (seconds/microseconds ignored).
        Upserts one ``mcp_aggregated_usage`` row per user that had usage in that
        minute, summing ``duration_ms`` and counting invocations. Returns the
        number of aggregated rows. Minutes with no usage produce no rows (the
        requirement: no row for no usage).
        """
        start = minute.replace(second=0, microsecond=0)
        end = start + timedelta(minutes=1)
        # Sum each raw metric column into its aggregated counterpart, aliasing
        # to the aggregated column name so the INSERT column list lines up.
        metric_sums = ", ".join(
            f"COALESCE(SUM(u.{raw}), 0) AS {agg}" for raw, agg in _AGGREGATED_METRIC_COLUMNS
        )
        agg_cols = ", ".join(agg for _raw, agg in _AGGREGATED_METRIC_COLUMNS)
        # ON CONFLICT (user_id, minute): refresh the row from a fresh full-minute
        # aggregate so a re-run after late raw rows is idempotent and correct.
        await self._session.execute(
            text(
                f"""
                INSERT INTO mcp_aggregated_usage (
                    id, minute, user_id, {_AGGREGATED_COUNT_COLUMN},
                    {agg_cols}
                )
                SELECT
                    gen_random_uuid(), :start, u.user_id,
                    COUNT(*) AS {_AGGREGATED_COUNT_COLUMN},
                    {metric_sums}
                FROM mcp_usage u
                WHERE u.created_at >= :start AND u.created_at < :end
                GROUP BY u.user_id
                ON CONFLICT (user_id, minute) DO UPDATE SET
                    {_AGGREGATED_COUNT_COLUMN} = EXCLUDED.{_AGGREGATED_COUNT_COLUMN},
                    {", ".join(f"{agg} = EXCLUDED.{agg}" for _raw, agg in _AGGREGATED_METRIC_COLUMNS)},
                    updated_at = now()
                """
            ),
            {"start": start, "end": end},
        )
        await self._session.commit()
        result = await self._session.execute(
            text(
                "SELECT COUNT(*) FROM mcp_aggregated_usage WHERE minute >= :start AND minute < :end"
            ),
            {"start": start, "end": end},
        )
        return int(result.scalar_one())

    async def aggregate_behind_now(
        self, *, lag_minutes: int = 1, now: datetime | None = None
    ) -> int:
        """Aggregate the most recent unprocessed finished minute.

        Processes the UTC minute that ended at least ``lag_minutes`` before
        *now* (default 1, so a finished minute is never partially aggregated).
        Returns the number of aggregated rows for that minute.
        """
        now = now or datetime.now(UTC)
        target = now - timedelta(minutes=lag_minutes)
        return await self.aggregate_minute(target)


__all__ = [
    "McpUsageService",
]
