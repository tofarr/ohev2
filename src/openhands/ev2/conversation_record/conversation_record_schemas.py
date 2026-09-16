"""Pydantic schemas for the conversation_record feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/conversation_records`` with
cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, and remove is ``DELETE``. The metric/cost/token columns default to 0
at creation and are updated via ``PATCH`` as events arrive from the ingestion
path.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.conversation_record.conversation_record_models import ConversationRecord
from openhands.ev2.event_callback.event_callback_models import EventCallback
from openhands.ev2.util.search_filter import BaseSearchFilter


class ConversationRecordCreate(BaseModel):
    """Payload to create a conversation_record.

    The metric columns (``accumulated_cost``, ``*_tokens``) are not accepted on
    create: they start at 0 and accumulate via ``PATCH`` from the ingestion
    path.
    """

    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(min_length=1)
    sandbox_config_id: uuid.UUID = Field(
        description="The sandbox config backing this conversation_record.",
    )
    llm_model: str = Field(min_length=1, description="LLM model identifier.")
    agent_kind: str = Field(min_length=1, description="Agent kind (e.g. 'openhands').")
    selected_repository: str | None = Field(
        default=None,
        description="Repository the conversation_record operates on; null when none.",
    )
    selected_branch: str | None = Field(
        default=None,
        description="Branch the conversation_record operates on; null when none.",
    )
    trigger: str = Field(
        min_length=1,
        description="What triggered the conversation_record (e.g. 'manual', 'webhook', 'automation').",
    )
    event_callbacks: list[EventCallback] = Field(
        default_factory=list,
        description="Embedded polymorphic EventCallback callables to attach.",
    )

    @field_validator("title", "llm_model", "agent_kind", "trigger")
    @classmethod
    def _strip_required(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ConversationRecordUpdate(BaseModel):
    """Payload to partially update a conversation_record. All fields optional.

    ``sandbox_config_id`` is immutable: the backing sandbox cannot change after
    creation. The metric columns are updated by the ingestion path as events
    arrive.
    """

    model_config = ConfigDict(populate_by_name=True)

    title: str | None = Field(default=None, min_length=1)
    llm_model: str | None = Field(default=None, min_length=1)
    agent_kind: str | None = Field(default=None, min_length=1)
    selected_repository: str | None = Field(default=None)
    selected_branch: str | None = Field(default=None)
    trigger: str | None = Field(default=None, min_length=1)
    accumulated_cost: float | None = Field(default=None, ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    event_callbacks: list[EventCallback] | None = None

    @field_validator("title", "llm_model", "agent_kind", "trigger")
    @classmethod
    def _strip_optional(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ConversationRecordRead(BaseModel):
    """ConversationRecord representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    sandbox_config_id: uuid.UUID
    llm_model: str
    agent_kind: str
    selected_repository: str | None
    selected_branch: str | None
    trigger: str
    accumulated_cost: float
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    event_callbacks: list[EventCallback] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ConversationRecordSearchFilter(BaseSearchFilter[ConversationRecord]):
    """Optional filter clauses for ``GET /conversation_records``.

    Field names follow the ``<attr>__<op>`` convention so the base class derives
    both the in-memory ``matches`` predicate and the SQL ``filter_sql`` clauses
    automatically. Every field is optional; an unset filter matches everything.
    """

    title__contains: str | None = Field(
        default=None, description="Case-insensitive title substring."
    )
    sandbox_config_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact backing sandbox config id match."
    )
    llm_model__eq: str | None = Field(default=None, description="Exact LLM model match.")
    agent_kind__eq: str | None = Field(default=None, description="Exact agent kind match.")
    selected_repository__eq: str | None = Field(default=None, description="Exact repository match.")
    selected_repository__contains: str | None = Field(
        default=None, description="Case-insensitive repository substring."
    )
    selected_branch__eq: str | None = Field(default=None, description="Exact branch match.")
    trigger__eq: str | None = Field(default=None, description="Exact trigger match.")
    created_at__gte: datetime | None = Field(
        default=None, description="ISO 8601; conversation_records created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; conversation_records created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; conversation_records created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; conversation_records created at or before."
    )


class ConversationRecordSearchResult(BaseModel):
    """Paginated collection of conversation_records."""

    items: list[ConversationRecordRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /conversation_records/batch applies create/update/delete
# atomically (AGENTS.md §3). Operations reuse ConversationRecordCreate/
# ConversationRecordUpdate; updates and deletes target a specific id.


class ConversationRecordBatchCreate(BaseModel):
    """Create operation within a conversation_record batch write."""

    op: Literal["create"] = "create"
    data: ConversationRecordCreate


class ConversationRecordBatchUpdate(BaseModel):
    """Update operation within a conversation_record batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: ConversationRecordUpdate


class ConversationRecordBatchDelete(BaseModel):
    """Delete operation within a conversation_record batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


ConversationRecordBatchOp = Annotated[
    ConversationRecordBatchCreate | ConversationRecordBatchUpdate | ConversationRecordBatchDelete,
    Field(discriminator="op"),
]


class ConversationRecordBatchWriteRequest(BaseModel):
    """Request body for ``POST /conversation_records/batch``."""

    operations: list[ConversationRecordBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
