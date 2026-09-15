"""ORM model and processor union for the event callback resource.

An :class:`EventCallback` is a durable, governed row that binds an SDK event
discriminator (``event_kind``) to a callable :class:`EventCallbackProcessor`.
A callback is linked to either a conversation or a conversation template —
exactly one of ``conversation_id`` / ``conversation_template_id`` is set
(enforced by a DB CHECK constraint and the service layer). Template-linked
callbacks are auto-attached to every conversation started from that template;
conversation-linked callbacks are attached at start or later.

Result state is merged onto the callback row itself (``status`` /
``detail`` / ``last_event_id`` / ``last_run_at``) — there is no separate
result object or table. The dispatch logic (issue #4) updates these columns
after invoking the processor; this issue provides storage + CRUD only.

Ownership is direct via ``creator_id``. Access is governed by the
``event_callback_permission`` role column; see ``event_callback_security`` and
AGENTS.md §11.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import Field
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)


class EventCallbackProcessor(DiscriminatedUnionMixin, ABC):
    """Abstract base for a callable event callback processor.

    A processor is a self-contained async callable that receives an SDK
    :class:`~openhands.sdk.event.Event` and performs its work. It stores
    whatever polymorphic state it needs in its own Pydantic fields, which are
    serialized to the callback row's ``processor`` JSONB column. No separate
    context object or result struct is passed or returned; the dispatch logic
    (issue #4) updates the callback row's ``status`` / ``detail`` /
    ``last_event_id`` / ``last_run_at`` columns after invoking the processor.

    Concrete variants participate in the SDK discriminated-union machinery (a
    ``kind`` computed field tags the concrete type) so a stored processor can be
    serialized to JSON and deserialized back to the right subclass. Additional
    variants will be introduced in future PRs.
    """

    @abstractmethod
    async def __call__(self, event: Any) -> None:
        """Invoke the processor for *event*.

        Concrete subclasses perform their work. The dispatch logic (issue #4)
        is responsible for catching exceptions and updating the callback row's
        merged result state.
        """


class LoggingCallbackProcessor(EventCallbackProcessor):
    """Reference processor that logs the event discriminator.

    A minimal variant that serves as the reference implementation for the
    :class:`EventCallbackProcessor` discriminated union. Its only state is an
    optional ``level`` (default ``"info"``); the dispatch logic (issue #4)
    wraps the :meth:`__call__` invocation and updates the callback row's merged
    result state.
    """

    level: str = Field(default="info", description="Log level (e.g. 'info', 'debug').")

    async def __call__(self, event: Any) -> None:
        """Log the event discriminator at the configured level.

        The actual logging side effect is performed here; the dispatch logic
        (issue #4) wraps this call and updates the callback row's merged result
        state. This reference implementation is intentionally minimal.
        """
        logging.getLogger("openhands.ev2.event_callback").log(
            getattr(logging, self.level.upper(), logging.INFO),
            "EventCallback fired for event: %r",
            event,
        )


class EventCallbackProcessorType(TypeDecorator[EventCallbackProcessor]):
    """SQLAlchemy column type that persists an :class:`EventCallbackProcessor` as JSONB.

    Stores the processor as a JSONB column on read/write, transparently
    serializing via ``model_dump`` and deserializing via the discriminated-union
    ``EventCallbackProcessor.model_validate`` so the round-trip restores the
    concrete subclass.
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: EventCallbackProcessor | dict[str, Any] | None,
        dialect: Any,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        return value.model_dump(mode="json")

    def process_result_value(
        self,
        value: dict[str, Any] | None,
        dialect: Any,
    ) -> EventCallbackProcessor | None:
        if value is None:
            return None
        return EventCallbackProcessor.model_validate(value)


class EventCallback(Base):
    """A governed event callback row with merged result state."""

    __tablename__ = "event_callbacks"
    __table_args__ = (
        # Exactly one of conversation_id / conversation_template_id must be set.
        CheckConstraint(
            "(conversation_id IS NOT NULL) <> (conversation_template_id IS NOT NULL)",
            name="event_callbacks_exactly_one_link",
        ),
        {"comment": "Event callbacks with merged result state (governed CRUD)"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    event_kind: Mapped[str] = mapped_column(
        String(255),
        comment="SDK event discriminator this callback fires on (e.g. 'MessageEvent').",
    )
    processor: Mapped[EventCallbackProcessor] = mapped_column(
        EventCallbackProcessorType,
        comment="Serialized EventCallbackProcessor discriminated union.",
    )
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
        default=None,
        comment="Conversation this callback is attached to; null when template-linked.",
    )
    conversation_template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversation_templates.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
        default=None,
        comment="Template this callback is auto-attached from; null when conversation-linked.",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="READY",
        server_default="READY",
        comment="Lifecycle/last-result state: READY/SUCCESS/ERROR/SKIPPED/DISABLED.",
    )
    detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Optional description of the current status.",
    )
    last_event_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        default=None,
        comment="UUID of the last event this callback was invoked for.",
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        nullable=True,
        default=None,
        comment="Timestamp of the last invocation.",
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
