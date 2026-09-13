"""Pydantic schemas for the event feature.

Events are immutable create/read-only resources: ``EventCreate`` accepts the
discriminator ``kind`` plus the event ``body`` payload; ``EventRead`` returns
the stored row (payload, or the truncation stub when the payload exceeded the
body cap) with its ``size_bytes`` always populated. There is no update schema.
Delete is only by partition retention, never via API.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.event.event_models import Event
from openhands.ev2.util.search_filter import BaseSearchFilter


class EventCreate(BaseModel):
    """Payload to create an event under a conversation."""

    model_config = ConfigDict(populate_by_name=True)

    kind: str = Field(min_length=1, description="Event discriminator.")
    body: dict[str, Any] = Field(description="Event payload.")

    @field_validator("kind")
    @classmethod
    def _strip_kind(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("kind must be a non-empty string")
        return v


class EventRead(BaseModel):
    """Event representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    conversation_id: uuid.UUID
    kind: str
    timestamp: datetime
    body: dict[str, Any]
    size_bytes: int


# Batch write: POST /conversations/{id}/events/batch applies creates
# atomically (AGENTS.md §3). Events are immutable, so the only op is
# create — no update/delete ops exist.


class EventBatchCreate(BaseModel):
    """Create operation within an event batch write."""

    op: Literal["create"] = "create"
    data: EventCreate


class EventBatchWriteRequest(BaseModel):
    """Request body for ``POST /conversations/{id}/events/batch``."""

    operations: list[EventBatchCreate] = Field(
        min_length=1,
        max_length=100,
        description="Create operations to apply atomically.",
    )


class EventSearchFilter(BaseSearchFilter[Event]):
    """Optional filter clauses for ``GET /conversations/{id}/events``.

    Field names follow the ``<attr>__<op>`` convention so the base class
    derives both the in-memory ``matches`` predicate and the SQL
    ``filter_sql`` clauses automatically. Every field is optional; an unset
    filter matches everything.
    """

    kind__eq: str | None = Field(default=None, description="Exact event kind match.")
    kind__contains: str | None = Field(default=None, description="Case-insensitive kind substring.")
    size_bytes__lt: int | None = Field(default=None, description="Original payload size below.")
    size_bytes__gte: int | None = Field(
        default=None, description="Original payload size at or above."
    )
    timestamp__gte: datetime | None = Field(
        default=None, description="ISO 8601; events at or after."
    )
    timestamp__lt: datetime | None = Field(default=None, description="ISO 8601; events before.")


class EventSearchResult(BaseModel):
    """Paginated collection of events for one conversation."""

    items: list[EventRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
