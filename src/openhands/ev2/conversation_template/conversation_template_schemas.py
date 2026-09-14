"""Pydantic schemas for the conversation template feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/conversation-templates``
with cursor pagination; create is ``POST``, update is ``PATCH``, retrieve is
``GET``, and remove is ``DELETE``. The ``agent_config`` / ``conversation_config``
blobs mirror how ``StoredLLM.config`` persists SDK fields verbatim: they are
opaque JSONB at this layer and validated/materialized by the start service
(issue #2).

List-typed references (``mcp_server_config_ids``, ``secret_provider_ids``,
``static_secret_ids``) are plain id lists — not DB FK columns — so the schemas
carry ``uuid.UUID`` objects and the service stringifies them for storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.conversation_template.conversation_template_models import (
    ConversationTemplate,
)
from openhands.ev2.util.search_filter import BaseSearchFilter

AgentKind = Literal["openhands", "acp"]


def _stringify_ids(ids: list[uuid.UUID]) -> list[str]:
    return [str(i) for i in ids]


def _parse_ids(values: list[str]) -> list[uuid.UUID]:
    return [uuid.UUID(v) for v in values]


class ConversationTemplateCreate(BaseModel):
    """Payload to create a conversation template."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    agent_kind: AgentKind = "openhands"
    llm_id: uuid.UUID | None = Field(
        default=None,
        description="FK to the governed StoredLLM to use; null = no default LLM.",
    )
    mcp_server_config_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Governed MCPServerConfig ids to load into conversations.",
    )
    secret_provider_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Governed SecretProvider ids to project into the secrets map.",
    )
    static_secret_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Governed StaticSecret ids to project into the secrets map.",
    )
    agent_config: dict[str, Any] = Field(
        default_factory=dict,
        description="SDK AgentSettings fields (minus llm/mcp/secrets, which are governed rows).",
    )
    conversation_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Template-level SDK ConversationConfig fields.",
    )
    system_message_suffix: str | None = Field(
        default=None,
        max_length=65536,
        description="Optional static suffix appended by the start service.",
    )
    default_callbacks: list[dict[str, Any]] = Field(
        default_factory=list,
        description="EventCallbackProcessor specs auto-attached by the start service.",
    )

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must be a non-empty string")
        return value


class ConversationTemplateUpdate(BaseModel):
    """Payload to partially update a conversation template. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    agent_kind: AgentKind | None = None
    llm_id: uuid.UUID | None = None
    mcp_server_config_ids: list[uuid.UUID] | None = None
    secret_provider_ids: list[uuid.UUID] | None = None
    static_secret_ids: list[uuid.UUID] | None = None
    agent_config: dict[str, Any] | None = None
    conversation_config: dict[str, Any] | None = None
    system_message_suffix: str | None = Field(default=None, max_length=65536)
    default_callbacks: list[dict[str, Any]] | None = None

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("name must be a non-empty string")
        return value


class ConversationTemplateRead(BaseModel):
    """Conversation template representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    name: str
    agent_kind: str
    llm_id: uuid.UUID | None
    mcp_server_config_ids: list[uuid.UUID] = Field(default_factory=list)
    secret_provider_ids: list[uuid.UUID] = Field(default_factory=list)
    static_secret_ids: list[uuid.UUID] = Field(default_factory=list)
    agent_config: dict[str, Any]
    conversation_config: dict[str, Any]
    system_message_suffix: str | None
    default_callbacks: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    @field_validator(
        "mcp_server_config_ids",
        "secret_provider_ids",
        "static_secret_ids",
        mode="before",
    )
    @classmethod
    def _parse_id_list(cls, value: list[str]) -> list[uuid.UUID]:
        return _parse_ids(value)


class ConversationTemplateSearchFilter(BaseSearchFilter[ConversationTemplate]):
    """Optional filter clauses for ``GET /conversation-templates``."""

    name__contains: str | None = Field(default=None, description="Case-insensitive name substring.")
    name__eq: str | None = Field(default=None, description="Exact name match.")
    agent_kind__eq: AgentKind | None = Field(default=None, description="Exact agent kind match.")
    llm_id__eq: uuid.UUID | None = Field(default=None, description="Exact LLM id match.")
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class ConversationTemplateSearchResult(BaseModel):
    """Paginated collection of conversation templates."""

    items: list[ConversationTemplateRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /conversation-templates/batch applies create/update/delete
# atomically (AGENTS.md §3). Operations reuse the single-item payloads; updates
# and deletes target a specific id.


class ConversationTemplateBatchCreate(BaseModel):
    """Create operation within a conversation template batch write."""

    op: Literal["create"] = "create"
    data: ConversationTemplateCreate


class ConversationTemplateBatchUpdate(BaseModel):
    """Update operation within a conversation template batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: ConversationTemplateUpdate


class ConversationTemplateBatchDelete(BaseModel):
    """Delete operation within a conversation template batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


ConversationTemplateBatchOp = Annotated[
    ConversationTemplateBatchCreate
    | ConversationTemplateBatchUpdate
    | ConversationTemplateBatchDelete,
    Field(discriminator="op"),
]


class ConversationTemplateBatchWriteRequest(BaseModel):
    """Request body for ``POST /conversation-templates/batch``."""

    operations: list[ConversationTemplateBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Create/update/delete operations applied atomically in one transaction.",
    )
