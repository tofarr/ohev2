"""ORM model for sandbox usage logging.

Mirrors the LLM/MCP usage logging shape: a background poll (see
:mod:`openhands.ev2.app`) records one :class:`SandboxUsage` row per claimed
sandbox (one carrying a ``sandbox_config_id``) each interval into the raw,
append-only ``sandbox_usage`` table — daily-partitioned by ``created_at`` so
old partitions can be dropped cheaply by the background partition manager,
exactly like ``llm_usage`` / ``mcp_usage``. Usage is keyed by the DB-backed
:class:`SandboxConfig` — not the provider-assigned sandbox id — so rows join
to ``sandbox_configs`` and from there to the owning user (``creator_id``)
and their groups. There is no aggregated projection: rows are periodic
snapshots, not request records, and the table is not exposed over REST.

``cpu`` / ``disk`` are nullable placeholders: the provider-neutral
:class:`~openhands.ev2.sandbox.sandbox_models.Sandbox` model does not yet
carry resource stats, so the poll leaves both blank (``NULL``) until the
sandbox services populate them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base


class SandboxUsage(Base):
    """One per-poll usage snapshot for a single sandbox config.

    One row per claimed sandbox (a sandbox with a ``sandbox_config_id``) per
    background poll interval. The table is PostgreSQL range-partitioned by
    ``created_at`` (one daily partition), so old partitions can be dropped
    cheaply by the background partition manager. The composite primary key
    ``(id, created_at)`` is required for partitioning (every column in the
    partition key must be part of the PK).

    Keyed by the DB-backed config so usage joins to the owning user and
    their groups through ``sandbox_configs``; unclaimed warm-pool sandboxes
    (no config yet) are not recorded. ``cpu`` and ``disk`` are ``NULL``
    until sandbox providers report resource stats.
    """

    __tablename__ = "sandbox_usage"
    __table_args__ = {  # noqa: RUF012
        "postgresql_partition_by": "RANGE(created_at)",
        "comment": "Per-poll per-sandbox-config usage snapshots, daily-partitioned by created_at",
    }

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Partition key — must be part of the PK and NOT NULL for range partitioning.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        init=False,
        server_default=func.clock_timestamp(),
        index=True,
    )
    # RESTRICT: a config with usage rows cannot be deleted — usage history
    # outlives the sandbox and must be cleaned up explicitly.
    sandbox_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_configs.id", ondelete="RESTRICT"),
        index=True,
    )
    cpu: Mapped[float | None] = mapped_column(Float, default=None)
    disk: Mapped[float | None] = mapped_column(Float, default=None)
