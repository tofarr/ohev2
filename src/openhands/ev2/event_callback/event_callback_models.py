"""Polymorphic event-callback model embedded on Conversation.

An :class:`EventCallback` is a polymorphic async callable that reacts to a
batch of SDK events. It is a Pydantic discriminated-union model (not an ORM
model and not a governed entity): it has no endpoints, DB table, CRUD schemas,
router, or service. Callbacks are stored as a JSONB ``event_callbacks`` list on
:class:`Conversation` (and ``default_callbacks`` on
:class:`ConversationTemplate`) and round-tripped via
:class:`EventCallbackListType`.

Per-kind filtering is intentionally dropped: there is no ``event_kind`` field.
Each callback receives a batch of the conversation's events and filters
internally as it requires. Dispatch/invocation and per-callback result
tracking are out of scope here — the future generic job queue owns them.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from openhands.sdk.event.base import Event
from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import Field
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

_LOGGER = logging.getLogger("openhands.ev2.event_callback")


class EventCallback(DiscriminatedUnionMixin, ABC):
    """A polymorphic async callable reacting to a batch of SDK events.

    Concrete variants participate in the SDK discriminated-union machinery (a
    ``kind`` computed field tags the concrete type) so a stored callback can be
    serialized to JSON and deserialized back to the right subclass.
    """

    @abstractmethod
    async def __call__(self, events: list[Event]) -> None:
        """Invoke the callback against a batch of *events*."""


class LoggingCallback(EventCallback):
    """Reference callback that logs every event in the batch."""

    level: str = Field(default="info", description="Log level (e.g. 'info', 'debug').")

    async def __call__(self, events: list[Event]) -> None:
        log = _LOGGER.log
        level = getattr(logging, self.level.upper(), logging.INFO)
        for event in events:
            log(level, "EventCallback fired for event: %r", event)


class EventCallbackListType(TypeDecorator[list[EventCallback]]):
    """SQLAlchemy column type persisting a ``list[EventCallback]`` as JSONB.

    Serializes each element via ``model_dump(mode="json")`` and deserializes
    via :meth:`EventCallback.model_validate`, restoring the concrete subclass
    on read. Precedent: ``security_models.PermissionType``.
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: list[EventCallback] | list[dict[str, Any]] | None,
        dialect: Any,
    ) -> list[dict[str, Any]] | None:
        if value is None:
            return None
        return [item if isinstance(item, dict) else item.model_dump(mode="json") for item in value]

    def process_result_value(
        self,
        value: list[dict[str, Any]] | None,
        dialect: Any,
    ) -> list[EventCallback] | None:
        if value is None:
            return None
        return [EventCallback.model_validate(item) for item in value]
