"""ORM models for proxied MCP tool usage logging.

Mirrors the LLM usage logging shape (``llm_usage`` / ``llm_aggregated_usage``)
so cumulative MCP tool-invocation duration and counts can be queried the same
way LLM token usage is.

* :class:`McpUsage` — raw, append-only record of a single proxied MCP
  ``tools/call`` invocation. One row per call; the table is PostgreSQL
  range-partitioned by ``created_at`` (one daily partition) so old partitions
  can be dropped cheaply by the background partition manager. The composite
  primary key ``(id, created_at)`` is required for partitioning; ``id`` is a
  bigint identity so the row is cheap to insert and orderable by recency.
  The wall-clock ``duration_ms`` spent inside the proxied upstream call is the
  primary metric, alongside ``tool_name`` and a success/error flag.
* :class:`McpAggregatedUsage` — per-minute, per-user rollup of
  :class:`McpUsage`. One row per ``(user_id, minute)`` that had at least one
  invocation; sums ``duration_ms`` and counts invocations. This is the table
  exposed read-only over REST.

The raw ``mcp_usage`` table is **not** exposed over REST — usage queries go
through the :class:`McpAggregatedUsage` projection. Background loops (see
:mod:`openhands.ev2.app`) keep future daily partitions allocated, drop expired
ones, and roll per-minute aggregations, exactly as for LLM usage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base


class McpUsage(Base):
    """Raw, append-only record of a single proxied MCP ``tools/call``.

    One row per proxied call. The table is PostgreSQL range-partitioned by
    ``created_at`` (one daily partition), so old partitions can be dropped
    cheaply by the background partition manager. The composite primary key
    ``(id, created_at)`` is required for partitioning (every column in the
    partition key must be part of the PK); ``id`` is a bigint identity so the
    row is cheap to insert and orderable by recency.

    ``duration_ms`` is the wall-clock time spent inside the proxied upstream
    MCP call (measured by the proxy endpoint around the forwarded request). It
    is the metric rolled into :class:`McpAggregatedUsage` so cumulative
    duration and invocation counts can be calculated in aggregation.

    This raw table is **not** exposed over REST — usage queries go through the
    :class:`McpAggregatedUsage` projection. Background loops keep future daily
    partitions allocated, drop expired ones, and roll per-minute aggregations.
    """

    __tablename__ = "mcp_usage"
    __table_args__ = {  # noqa: RUF012
        "postgresql_partition_by": "RANGE(created_at)",
        "comment": "Raw proxied MCP tool-invocation records, daily-partitioned by created_at",
    }

    id: Mapped[int] = mapped_column(
        BigInteger,
        sa.Identity(always=False, start=1, increment=1),
        primary_key=True,
        init=False,
    )
    # Partition key — must be part of the PK and NOT NULL for range partitioning.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        init=False,
        server_default=func.now(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    mcp_server_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("mcp_server_configs.id", ondelete="CASCADE"),
        index=True,
    )
    # The MCP tool name from the ``tools/call`` request params; "" when absent.
    tool_name: Mapped[str] = mapped_column(String(255), default="", server_default="")
    # Wall-clock duration of the proxied upstream call, in milliseconds.
    duration_ms: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    success: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    error: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    # Full JSON-RPC response dump for any detail not lifted into a dedicated
    # column. Keeps the raw record forward-compatible without a migration.
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Full JSON-RPC response dump (model_dump(mode='json')).",
    )


class McpAggregatedUsage(Base):
    """Per-minute, per-user rollup of :class:`McpUsage` for usage queries.

    One row per ``(user_id, minute)`` that had at least one invocation. Sums
    ``duration_ms`` and counts invocations; the background aggregator populates
    it one minute at a time, always at least one minute behind real time so a
    finished minute is never partially aggregated. Minutes without usage are
    not inserted (the requirement is "no row for no usage").

    This is the table exposed read-only over REST
    (``/mcp-server-configs/aggregated-usage``).
    """

    __tablename__ = "mcp_aggregated_usage"
    __table_args__ = (
        UniqueConstraint("user_id", "minute", name="uq_mcp_aggregated_usage_user_id_minute"),
        {"comment": "Per-minute, per-user rollup of mcp_usage"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # UTC minute bucket (seconds zeroed) — the aggregation grain.
    minute: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    invocations: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    total_duration_ms: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


__all__ = [
    "McpAggregatedUsage",
    "McpUsage",
]
