"""Service layer for LLM usage logging.

Three concerns, each a small single-purpose method:

* :meth:`LlmUsageService.record_usage` — append a raw :class:`LlmUsage` row
  after a proxied completion. Called from the completion router; never raises
  into the response path (the caller has already returned the completion), so a
  logging failure is swallowed and logged rather than failing the request.
* :meth:`LlmUsageService.ensure_partitions` — allocate future daily partitions
  of the range-partitioned ``llm_usage`` table and drop expired ones. Driven by
  the background partition-manager loop.
* :meth:`LlmUsageService.aggregate_minute` — roll one finished UTC minute of
  ``llm_usage`` into ``llm_aggregated_usage`` (upserting per-user sums + an
  invocation count). Driven by the background aggregator loop, which always
  processes the minute that ended at least one minute before wall-clock time so
  a finished minute is never partially aggregated.

The raw ``llm_usage`` table is not exposed over REST; the read-only
``llm_aggregated_usage`` projection is served by :mod:`openhands.ev2.llm.llm_router`.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.llm.llm_models import LlmUsage

logger = logging.getLogger(__name__)

# Metric columns rolled from raw usage into the aggregated projection. Kept in
# one place so the aggregator SQL and the record builder stay in sync.
_AGGREGATED_METRIC_COLUMNS: tuple[str, ...] = (
    "prompt_tokens",
    "completion_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "context_window",
    "per_turn_token",
)
# accumulated_cost is a float sum, not a bigint; handled separately in the SQL.
_COST_COLUMN = "accumulated_cost"


def _extract_metrics(sdk_metrics: Any) -> dict[str, Any]:
    """Reduce an SDK ``MetricsSnapshot`` to the ``LlmUsage`` column values.

    Pulls the per-call token counts out of ``accumulated_token_usage`` (the SDK
    stores the *accumulated* usage across calls; for a single proxied call we
    record the values reported on that response). Missing fields default to 0.
    """
    if sdk_metrics is None:
        usage: dict[str, Any] = {}
    else:
        dump = (
            sdk_metrics.model_dump(mode="json")
            if hasattr(sdk_metrics, "model_dump")
            else dict(sdk_metrics)
        )
        usage = (dump.get("accumulated_token_usage") or {}) if isinstance(dump, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    return {
        "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
        "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
        "cache_read_tokens": int(usage.get("cache_read_tokens", 0) or 0),
        "cache_write_tokens": int(usage.get("cache_write_tokens", 0) or 0),
        "reasoning_tokens": int(usage.get("reasoning_tokens", 0) or 0),
        "context_window": int(usage.get("context_window", 0) or 0),
        "per_turn_token": int(usage.get("per_turn_token", 0) or 0),
    }


def _partition_name(day: datetime) -> str:
    """The daily partition table name for *day* (a UTC date)."""
    return f"llm_usage_{day.strftime('%Y%m%d')}"


def _day_bounds(day: datetime) -> tuple[str, str]:
    """The ``[from, to)`` DATE bounds for the *day* partition (ISO strings)."""
    start = day.date().isoformat()
    end = (day + timedelta(days=1)).date().isoformat()
    return start, end


class LlmUsageService:
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
        provider_connection_id: uuid.UUID,
        llm_id: uuid.UUID | None,
        response_id: str | None,
        model: str,
        sdk_metrics: Any,
    ) -> LlmUsage | None:
        """Append a raw usage row for one completion.

        Returns the inserted row, or ``None`` when the insert failed (a missing
        partition for the current day is the likely cause — the partition
        manager should have allocated it). The caller must not let a failure
        here surface to the user; the completion has already succeeded.
        """
        metrics = _extract_metrics(sdk_metrics)
        cost = 0.0
        if sdk_metrics is not None:
            dump = (
                sdk_metrics.model_dump(mode="json")
                if hasattr(sdk_metrics, "model_dump")
                else dict(sdk_metrics)
            )
            if isinstance(dump, dict):
                cost = float(dump.get("accumulated_cost", 0.0) or 0.0)
        full_dump = (
            sdk_metrics.model_dump(mode="json")
            if sdk_metrics is not None and hasattr(sdk_metrics, "model_dump")
            else {}
        )
        row = LlmUsage(
            user_id=user_id,
            provider_connection_id=provider_connection_id,
            llm_id=llm_id,
            response_id=response_id,
            model=model,
            accumulated_cost=cost,
            metrics=full_dump,
            **metrics,
        )
        try:
            self._session.add(row)
            await self._session.flush()
            return row
        except Exception:
            await self._session.rollback()
            logger.exception("failed to record llm usage row")
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
            text("CREATE TABLE IF NOT EXISTS llm_usage_default PARTITION OF llm_usage DEFAULT")
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
                f"CREATE TABLE {name} PARTITION OF llm_usage "
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
                    "WHERE inhparent = 'llm_usage'::regclass "
                    "AND inhrelid::regclass::text LIKE 'llm_usage_%'"
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
                continue  # not a dated partition (e.g. llm_usage_default is filtered by the LIKE)
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
        Upserts one ``llm_aggregated_usage`` row per user that had usage in that
        minute, summing token/metric columns + ``accumulated_cost`` and counting
        invocations. Returns the number of aggregated rows. Minutes with no
        usage produce no rows (the requirement: no row for no usage).
        """
        start = minute.replace(second=0, microsecond=0)
        end = start + timedelta(minutes=1)
        cols = ", ".join(f"COALESCE(SUM(u.{c}), 0) AS {c}" for c in _AGGREGATED_METRIC_COLUMNS)
        # ON CONFLICT (user_id, minute): refresh the row from a fresh full-minute
        # aggregate so a re-run after late raw rows is idempotent and correct.
        await self._session.execute(
            text(
                f"""
                INSERT INTO llm_aggregated_usage (
                    id, minute, user_id, invocations,
                    prompt_tokens, completion_tokens, cache_read_tokens,
                    cache_write_tokens, reasoning_tokens, context_window,
                    per_turn_token, accumulated_cost
                )
                SELECT
                    gen_random_uuid(), :start, u.user_id, COUNT(*) AS invocations,
                    {cols},
                    COALESCE(SUM(u.{_COST_COLUMN}), 0) AS {_COST_COLUMN}
                FROM llm_usage u
                WHERE u.created_at >= :start AND u.created_at < :end
                GROUP BY u.user_id
                ON CONFLICT (user_id, minute) DO UPDATE SET
                    invocations = EXCLUDED.invocations,
                    prompt_tokens = EXCLUDED.prompt_tokens,
                    completion_tokens = EXCLUDED.completion_tokens,
                    cache_read_tokens = EXCLUDED.cache_read_tokens,
                    cache_write_tokens = EXCLUDED.cache_write_tokens,
                    reasoning_tokens = EXCLUDED.reasoning_tokens,
                    context_window = EXCLUDED.context_window,
                    per_turn_token = EXCLUDED.per_turn_token,
                    accumulated_cost = EXCLUDED.accumulated_cost,
                    updated_at = now()
                """
            ),
            {"start": start, "end": end},
        )
        await self._session.commit()
        result = await self._session.execute(
            text(
                "SELECT COUNT(*) FROM llm_aggregated_usage WHERE minute >= :start AND minute < :end"
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
    "LlmUsageService",
]
