"""Pydantic schemas for the event callback feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/event-callbacks``
with cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, and remove is ``DELETE``. Batch read + batch write and count are also
provided.

A callback is linked to either a conversation or a conversation template —
exactly one of ``conversation_id`` / ``conversation_template_id`` is set. The
schemas express this as two optional fields; the service layer enforces the
exactly-one invariant (and the DB CHECK constraint backstops it).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from openhands.ev2.event_callback.event_callback_models import (
    EventCallback,
    EventCallbackProcessor,
)
from openhands.ev2.util.search_filter import BaseSearchFilter

EventCallbackStatus = Literal["READY", "SUCCESS", "ERROR", "SKIPPED", "DISABLED"]


class EventCallbackCreate(BaseModel):
    """Payload to create an event callback.

    Exactly one of ``conversation_id`` / ``conversation_template_id`` must be
    set; setting both or neither is a validation error.
    """

    model_config = ConfigDict(populate_by_name=True)

    event_kind: str = Field(min_length=1, max_length=255)
    processor: EventCallbackProcessor
    conversation_id: uuid.UUID | None = Field(
        default=None,
        description="Conversation this callback is attached to; null when template-linked.",
    )
    conversation_template_id: uuid.UUID | None = Field(
        default=None,
        description="Template this callback is auto-attached from; null when conversation-linked.",
    )

    @field_validator("event_kind")
    @classmethod
    def _strip_event_kind(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("event_kind must be a non-empty string")
        return value

    @model_validator(mode="after")
    def _exactly_one_link(self) -> EventCallbackCreate:
        if (self.conversation_id is None) == (self.conversation_template_id is None):
            raise ValueError(
                "Exactly one of conversation_id / conversation_template_id must be set."
            )
        return self


class EventCallbackUpdate(BaseModel):
    """Payload to partially update an event callback. All fields optional.

    The link fields (``conversation_id`` / ``conversation_template_id``) may be
    changed, but the exactly-one invariant is re-validated at the service
    layer against the merged row. The merged-result state fields
    (``status`` / ``detail`` / ``last_event_id`` / ``last_run_at``) are writable
    so the dispatch logic (issue #4) can update them; the CRUD resource does
    not restrict them.
    """

    model_config = ConfigDict(populate_by_name=True)

    event_kind: str | None = Field(default=None, min_length=1, max_length=255)
    processor: EventCallbackProcessor | None = None
    conversation_id: uuid.UUID | None = None
    conversation_template_id: uuid.UUID | None = None
    status: EventCallbackStatus | None = None
    detail: str | None = Field(default=None, max_length=65536)
    last_event_id: uuid.UUID | None = None
    last_run_at: datetime | None = None

    @field_validator("event_kind")
    @classmethod
    def _strip_event_kind(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("event_kind must be a non-empty string")
        return value

    @model_validator(mode="after")
    def _exactly_one_link_when_both_set(self) -> EventCallbackUpdate:
        # When both link fields are explicitly set in the same update, the
        # exactly-one invariant is violated regardless of the stored row.
        if self.conversation_id is not None and self.conversation_template_id is not None:
            raise ValueError(
                "Exactly one of conversation_id / conversation_template_id must be set."
            )
        return self


class EventCallbackRead(BaseModel):
    """Event callback representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    event_kind: str
    processor: EventCallbackProcessor
    conversation_id: uuid.UUID | None
    conversation_template_id: uuid.UUID | None
    status: str
    detail: str | None
    last_event_id: uuid.UUID | None
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime


class EventCallbackSearchFilter(BaseSearchFilter[EventCallback]):
    """Optional filter clauses for ``GET /event-callbacks``."""

    event_kind__contains: str | None = Field(
        default=None, description="Case-insensitive event_kind substring."
    )
    event_kind__eq: str | None = Field(default=None, description="Exact event_kind match.")
    status__eq: EventCallbackStatus | None = Field(default=None, description="Exact status match.")
    conversation_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact conversation_id match."
    )
    conversation_template_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact conversation_template_id match."
    )
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class EventCallbackSearchResult(BaseModel):
    """Paginated collection of event callbacks."""

    items: list[EventCallbackRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /event-callbacks/batch applies create/update/delete
# atomically (AGENTS.md §3). Operations reuse the single-item payloads; updates
# and deletes target a specific id.


class EventCallbackBatchCreate(BaseModel):
    """Create operation within an event callback batch write."""

    op: Literal["create"] = "create"
    data: EventCallbackCreate


class EventCallbackBatchUpdate(BaseModel):
    """Update operation within an event callback batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: EventCallbackUpdate


class EventCallbackBatchDelete(BaseModel):
    """Delete operation within an event callback batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


EventCallbackBatchOp = Annotated[
    EventCallbackBatchCreate | EventCallbackBatchUpdate | EventCallbackBatchDelete,
    Field(discriminator="op"),
]


class EventCallbackBatchWriteRequest(BaseModel):
    """Request body for ``POST /event-callbacks/batch``."""

    operations: list[EventCallbackBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Create/update/delete operations applied atomically in one transaction.",
    )
