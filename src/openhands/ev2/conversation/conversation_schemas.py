"""Pydantic schemas for the conversation feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/conversations`` with
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

from openhands.ev2.conversation.conversation_models import Conversation
from openhands.ev2.util.search_filter import BaseSearchFilter


class ConversationCreate(BaseModel):
    """Payload to create a conversation.

    The metric columns (``accumulated_cost``, ``*_tokens``) are not accepted on
    create: they start at 0 and accumulate via ``PATCH`` from the ingestion
    path.
    """

    model_config = ConfigDict(populate_by_name=True)

    title: str = Field(min_length=1)
    sandbox_config_id: uuid.UUID = Field(
        description="The sandbox config backing this conversation.",
    )
    llm_model: str = Field(min_length=1, description="LLM model identifier.")
    agent_kind: str = Field(min_length=1, description="Agent kind (e.g. 'openhands').")
    selected_repository: str | None = Field(
        default=None,
        description="Repository the conversation operates on; null when none.",
    )
    selected_branch: str | None = Field(
        default=None,
        description="Branch the conversation operates on; null when none.",
    )
    trigger: str = Field(
        min_length=1,
        description="What triggered the conversation (e.g. 'manual', 'webhook', 'automation').",
    )

    @field_validator("title", "llm_model", "agent_kind", "trigger")
    @classmethod
    def _strip_required(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ConversationUpdate(BaseModel):
    """Payload to partially update a conversation. All fields optional.

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

    @field_validator("title", "llm_model", "agent_kind", "trigger")
    @classmethod
    def _strip_optional(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ConversationRead(BaseModel):
    """Conversation representation returned by the API."""

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
    created_at: datetime
    updated_at: datetime


class ConversationSearchFilter(BaseSearchFilter[Conversation]):
    """Optional filter clauses for ``GET /conversations``.

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
        default=None, description="ISO 8601; conversations created at or after."
    )
    created_at__lt: datetime | None = Field(
        default=None, description="ISO 8601; conversations created before."
    )
    created_at__gt: datetime | None = Field(
        default=None, description="ISO 8601; conversations created strictly after."
    )
    created_at__lte: datetime | None = Field(
        default=None, description="ISO 8601; conversations created at or before."
    )


class ConversationSearchResult(BaseModel):
    """Paginated collection of conversations."""

    items: list[ConversationRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /conversations/batch applies create/update/delete
# atomically (AGENTS.md §3). Operations reuse ConversationCreate/
# ConversationUpdate; updates and deletes target a specific id.


class ConversationBatchCreate(BaseModel):
    """Create operation within a conversation batch write."""

    op: Literal["create"] = "create"
    data: ConversationCreate


class ConversationBatchUpdate(BaseModel):
    """Update operation within a conversation batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: ConversationUpdate


class ConversationBatchDelete(BaseModel):
    """Delete operation within a conversation batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


ConversationBatchOp = Annotated[
    ConversationBatchCreate | ConversationBatchUpdate | ConversationBatchDelete,
    Field(discriminator="op"),
]


class ConversationBatchWriteRequest(BaseModel):
    """Request body for ``POST /conversations/batch``."""

    operations: list[ConversationBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )
