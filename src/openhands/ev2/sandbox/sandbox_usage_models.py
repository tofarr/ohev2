"""ORM model for sandbox usage logging.

Mirrors the LLM/MCP usage logging shape at a smaller scale: a background poll
(see :mod:`openhands.ev2.app`) records one :class:`SandboxUsage` row per
sandbox known to the configured ``SandboxService`` each interval. Unlike
``llm_usage`` / ``mcp_usage`` the table is not event-driven and not
partitioned — rows are periodic snapshots, not request records.

``cpu`` / ``disk`` are nullable placeholders: the provider-neutral
:class:`~openhands.ev2.sandbox.sandbox_models.Sandbox` model does not yet
carry resource stats, so the poll leaves both blank (``NULL``) until the
sandbox services populate them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from openhands.ev2.db import Base


class SandboxUsage(Base):
    """One per-poll usage snapshot for a single sandbox.

    One row per sandbox per background poll interval. ``sandbox_id`` is the
    provider-assigned sandbox id (a plain string — live sandboxes are
    provider-backed, not DB rows, so there is no foreign key). ``cpu`` and
    ``disk`` are ``NULL`` until sandbox providers report resource stats.
    """

    __tablename__ = "sandbox_usage"
    __table_args__ = {  # noqa: RUF012
        "comment": "Per-poll per-sandbox usage snapshots recorded by the background poll",
    }

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        init=False,
        server_default=func.clock_timestamp(),
        index=True,
    )
    # Provider-assigned sandbox id; not an FK (live sandboxes are not DB rows).
    sandbox_id: Mapped[str] = mapped_column(String(255), index=True)
    cpu: Mapped[float | None] = mapped_column(Float, default=None)
    disk: Mapped[float | None] = mapped_column(Float, default=None)
