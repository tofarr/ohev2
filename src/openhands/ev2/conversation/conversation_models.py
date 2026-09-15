"""ORM model for the conversation resource.

A :class:`Conversation` is the durable record of an agent conversation backed
by a sandbox (``sandbox_config_id`` -> ``sandbox_configs``). Rows are populated
by the webhook ingestion path; this feature provides storage + CRUD only. The
metric columns (``accumulated_cost``, ``prompt_tokens``, ``completion_tokens``,
``total_tokens``) start at 0 and are updated via ``PATCH`` as events arrive.

``event_callbacks`` is a JSONB list of polymorphic
:class:`~openhands.ev2.event_callback.event_callback_models.EventCallback`
callables embedded on the conversation, round-tripped via
:class:`EventCallbackListType`. Dispatch is out of scope (the future generic
job queue owns it).

Ownership is deliberately indirect: a conversation has no ``creator_id`` of its
own. Access for non-admin users derives from the backing sandbox config's
creator (see ``conversation_security.ConversationAccess``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.event_callback.event_callback_models import (
    EventCallback,
    EventCallbackListType,
)
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig

_TZ = DateTime(timezone=True)


class Conversation(Base):
    """A conversation backed by a sandbox config."""

    __tablename__ = "conversations"
    __table_args__ = {"comment": "Agent conversations backed by sandbox configs"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    title: Mapped[str] = mapped_column(Text)
    sandbox_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_configs.id", ondelete="CASCADE"),
        index=True,
    )
    llm_model: Mapped[str] = mapped_column(
        Text,
        comment="LLM model identifier used for the conversation.",
    )
    agent_kind: Mapped[str] = mapped_column(
        Text,
        comment="Agent kind (e.g. 'openhands').",
    )
    trigger: Mapped[str] = mapped_column(
        Text,
        comment="What triggered the conversation (e.g. 'manual', 'webhook', 'automation').",
    )
    selected_repository: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Repository the conversation operates on; null when none.",
    )
    selected_branch: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Branch the conversation operates on; null when none.",
    )
    accumulated_cost: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        server_default="0",
        comment="Accumulated cost in USD; updated via PATCH as events arrive.",
    )
    prompt_tokens: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        server_default="0",
        comment="Accumulated prompt tokens; updated via PATCH as events arrive.",
    )
    completion_tokens: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        server_default="0",
        comment="Accumulated completion tokens; updated via PATCH as events arrive.",
    )
    total_tokens: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        server_default="0",
        comment="Accumulated total tokens; updated via PATCH as events arrive.",
    )
    event_callbacks: Mapped[list[EventCallback]] = mapped_column(
        EventCallbackListType,
        default_factory=list,
        comment="Embedded polymorphic EventCallback callables for this conversation.",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )

    # Loaded eagerly so the in-memory ownership check in
    # ConversationAccessFilter.matches can resolve the backing config's
    # creator without a lazy load (AGENTS.md: asyncio-first, no implicit I/O).
    sandbox_config: Mapped[SandboxConfig] = relationship(init=False, lazy="selectin")
