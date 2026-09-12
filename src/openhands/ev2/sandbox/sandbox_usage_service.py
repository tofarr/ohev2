"""Service layer for sandbox usage logging.

Two concerns, each a small single-purpose method (mirrors
:mod:`openhands.ev2.mcp_server_config.mcp_usage_service`, minus aggregation —
sandbox usage has no aggregated projection):

* :meth:`SandboxUsageService.record_usage` — append one
  :class:`~openhands.ev2.sandbox.sandbox_usage_models.SandboxUsage` row per
  claimed sandbox, keyed by ``sandbox_config_id`` so usage associates with
  the DB-backed config and through it the owning user and their groups.
  Driven by the background poll loop (config ``sandbox_usage_interval``).
* :meth:`SandboxUsageService.ensure_partitions` — allocate future daily
  partitions of the range-partitioned ``sandbox_usage`` table and drop
  expired ones. Driven by the background partition-manager loop (config
  ``sandbox_usage_partition_interval``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import Sandbox
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage


def _partition_name(day: datetime) -> str:
    """The daily partition table name for *day* (a UTC date)."""
    return f"sandbox_usage_{day.strftime('%Y%m%d')}"


def _day_bounds(day: datetime) -> tuple[str, str]:
    """The ``[from, to)`` DATE bounds for the *day* partition (ISO strings)."""
    start = day.date().isoformat()
    end = (day + timedelta(days=1)).date().isoformat()
    return start, end


class SandboxUsageService:
    """Records per-poll sandbox usage snapshots and manages daily partitions."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    async def record_usage(self, sandboxes: Iterable[Sandbox]) -> int:
        """Append one usage row per claimed sandbox and return the count.

        Sandboxes without a ``sandbox_config_id`` (unclaimed warm-pool
        sandboxes) are skipped — usage is tracked against the DB-backed
        config, not the provider sandbox. ``cpu`` / ``disk`` are left
        ``NULL`` — the :class:`Sandbox` model does not carry resource stats
        yet; providers will populate them later.
        """
        rows = [
            SandboxUsage(sandbox_config_id=uuid.UUID(sandbox.sandbox_config_id))
            for sandbox in sandboxes
            if sandbox.sandbox_config_id
        ]
        if not rows:
            return 0
        self._session.add_all(rows)
        await self._session.commit()
        return len(rows)

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
        skipped. A ``DEFAULT`` partition is ensured once so inserts never
        fail if the manager falls behind.

        *now* defaults to the current UTC time; pass it for deterministic tests.
        """
        now = now or datetime.now(UTC)
        created: list[str] = []
        # Allocate today + the next ``preallocate_days - 1`` days.
        for offset in range(preallocate_days):
            day = (now + timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            name = await self._ensure_partition(day)
            if name is not None:
                created.append(name)
        # Ensure a DEFAULT partition so inserts never fail when the manager
        # falls behind (rows there are queryable until their day is dropped).
        await self._session.execute(
            text(
                "CREATE TABLE IF NOT EXISTS sandbox_usage_default "
                "PARTITION OF sandbox_usage DEFAULT"
            )
        )
        dropped = await self._drop_expired_partitions(retention_days, now)
        await self._session.commit()
        return created, dropped

    async def _ensure_partition(self, day: datetime) -> str | None:
        """Create the daily partition for *day* if absent; return its name or None."""
        name = _partition_name(day)
        start, end = _day_bounds(day)
        # pg_class check avoids a CREATE that would raise on an existing
        # partition and makes the "created vs skipped" distinction explicit.
        exists = (
            await self._session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = :n"), {"n": name}
            )
        ).scalar_one_or_none()
        if exists is not None:
            return None
        await self._session.execute(
            text(
                f"CREATE TABLE {name} PARTITION OF sandbox_usage "
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
                    "WHERE inhparent = 'sandbox_usage'::regclass "
                    "AND inhrelid::regclass::text LIKE 'sandbox_usage_%'"
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
                continue  # not a dated partition (e.g. sandbox_usage_default)
            if day < cutoff:
                await self._session.execute(text(f"DROP TABLE IF EXISTS {name}"))
                dropped.append(name)
        return dropped
