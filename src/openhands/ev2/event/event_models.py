"""ORM model for the event resource.

An :class:`Event` is one immutable record of a conversation event (an agent
message, tool call, observation, …). The ``events`` table is a PostgreSQL
range-partitioned projection on ``timestamp`` — one daily partition, managed
by the background partition-manager loop (mirroring ``llm_usage`` /
``mcp_usage`` / ``sandbox_usage``). The composite primary key
``(id, timestamp)`` is required for partitioning (every column in the
partition key must be part of the PK).

The ``body`` column holds the real payload when the serialized body is within
the configured cap, or a self-describing truncation stub when over cap —
stored-then-read (not NULL-then-synthesize) so the row is honest and queryable
(``WHERE body->>'_truncated' = 'true'``). ``size_bytes`` always carries the
original payload size. The full body of every event (not just the oversized
ones) is written to the backing store at a key derivable from the event's own
identity (``<event_date>/<event_id[:2]>/<event_id>.json``), so there is no
``body_uri`` column — the table is identical in every deployment shape.

Ownership is deliberately indirect: like :class:`Conversation`, an event has
no ``creator_id``. Access for non-admin users derives from the parent
conversation's backing sandbox config's creator (see
``event_security.EventAccess``); the ``conversation`` relationship is loaded
eagerly (``selectin``) so the in-memory ownership check needs no lazy load
(AGENTS.md: asyncio-first, no implicit I/O).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class Event(Base):
    """One conversation event row in the partitioned projection."""

    __tablename__ = "events"
    __table_args__ = {  # noqa: RUF012
        "postgresql_partition_by": "RANGE(timestamp)",
        "comment": "Conversation event projection, daily-partitioned by timestamp",
    }

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Partition key — must be part of the PK and NOT NULL for range
    # partitioning. ``timestamp`` (not ``created_at``) is the event's own time.
    timestamp: Mapped[datetime] = mapped_column(
        _TZ,
        primary_key=True,
        init=False,
        server_default=func.clock_timestamp(),
    )
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"),
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        Text,
        comment="Event discriminator (e.g. 'message', 'observation').",
    )
    body: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        comment=(
            "Event payload when within the body cap; a truncation stub "
            "({'_truncated': true, 'original_size_bytes', 'preview'}) when "
            "over cap. The full body is always in the backing store."
        ),
    )
    size_bytes: Mapped[int] = mapped_column(
        Integer,
        comment="Original serialized payload size in bytes, always populated.",
    )

    # Loaded eagerly so the in-memory ownership check in
    # EventAccessFilter.matches can resolve the backing sandbox config's
    # creator without a lazy load (see Conversation.sandbox_config).
    conversation: Mapped[Conversation] = relationship(init=False, lazy="selectin")
