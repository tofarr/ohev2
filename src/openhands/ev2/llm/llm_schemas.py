"""Pydantic schemas for the LLM feature.

Uniform REST surface (AGENTS.md §3): the collections are
``/provider-connections`` and ``/llms`` with cursor pagination; create is
``POST``, retrieve is ``GET``, update is ``PATCH``, remove is ``DELETE``.
A ``POST /llm/completion/{llm_id}`` action endpoint proxies a completion
request through a stored LLM profile, inferring the provider connection from
the LLM.

The ``api_key`` on a provider connection is write-only: it appears in
``ProviderConnectionCreate``/``ProviderConnectionUpdate`` (plaintext over the
wire, encrypted before persistence) but is never returned by the API
(``ProviderConnectionRead`` omits it). The ``config`` on a stored LLM is an
opaque JSON blob of SDK :class:`LLM` fields minus the connection-sourced ones.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openhands.ev2.llm.llm_models import (
    LlmAggregatedUsage,
    StoredLLM,
    StoredProviderConnection,
)
from openhands.ev2.util.search_filter import BaseSearchFilter

# ---------------------------------------------------------------------- #
# Provider connection
# ---------------------------------------------------------------------- #


class ProviderConnectionCreate(BaseModel):
    """Payload to create a provider connection.

    ``api_key`` is plaintext over the wire; encrypted with the encryption
    service before persistence. Never returned by the API.
    """

    model_config = ConfigDict(populate_by_name=True)

    display_name: str = Field(min_length=1, max_length=128)
    provider: str = Field(default="custom", min_length=1, max_length=128)
    api_key: str | None = Field(default=None, description="Plaintext API key; encrypted at rest.")
    base_url: str | None = Field(default=None, max_length=2048)
    enable_proxy: bool = False

    @field_validator("display_name", "provider")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ProviderConnectionUpdate(BaseModel):
    """Payload to partially update a provider connection. All fields optional."""

    model_config = ConfigDict(populate_by_name=True)

    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    provider: str | None = Field(default=None, min_length=1, max_length=128)
    api_key: str | None = Field(default=None, description="Plaintext API key; encrypted at rest.")
    base_url: str | None = Field(default=None, max_length=2048)
    enable_proxy: bool | None = None

    @field_validator("display_name", "provider")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class ProviderConnectionRead(BaseModel):
    """Provider connection representation returned by the API.

    The ``api_key`` is intentionally omitted: it is write-only.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    display_name: str
    provider: str
    base_url: str | None
    enable_proxy: bool
    created_at: datetime
    updated_at: datetime


class ProviderConnectionSearchFilter(BaseSearchFilter[StoredProviderConnection]):
    """Optional filter clauses for `GET /provider-connections`."""

    display_name__contains: str | None = Field(
        default=None, description="Case-insensitive display name substring."
    )
    provider__eq: str | None = Field(default=None, description="Exact provider match.")
    enable_proxy__eq: bool | None = Field(default=None, description="Exact enable_proxy match.")
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class ProviderConnectionSearchResult(BaseModel):
    """Paginated collection of provider connections."""

    items: list[ProviderConnectionRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /provider-connections/batch applies create/update/delete
# atomically (AGENTS.md §3). Operations reuse the single-item payloads; updates
# and deletes target a specific id.


class ProviderConnectionBatchCreate(BaseModel):
    """Create operation within a provider-connection batch write."""

    op: Literal["create"] = "create"
    data: ProviderConnectionCreate


class ProviderConnectionBatchUpdate(BaseModel):
    """Update operation within a provider-connection batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: ProviderConnectionUpdate


class ProviderConnectionBatchDelete(BaseModel):
    """Delete operation within a provider-connection batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


ProviderConnectionBatchOp = Annotated[
    ProviderConnectionBatchCreate | ProviderConnectionBatchUpdate | ProviderConnectionBatchDelete,
    Field(discriminator="op"),
]


class ProviderConnectionBatchWriteRequest(BaseModel):
    """Request body for `POST /provider-connections/batch`."""

    operations: list[ProviderConnectionBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )


# ---------------------------------------------------------------------- #
# LLM
# ---------------------------------------------------------------------- #


class LLMCreate(BaseModel):
    """Payload to create a stored LLM profile.

    ``config`` is an opaque JSON blob of SDK :class:`LLM` fields excluding
    ``model`` (top-level), and the connection-sourced ``provider``/``api_key``/
    ``base_url``/``provider_connection_id``. The service validates it by
    constructing an SDK :class:`LLM` from it + the linked connection.
    """

    model_config = ConfigDict(populate_by_name=True)

    provider_connection_id: uuid.UUID
    model: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=128)
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="SDK LLM config (fields except model/provider/api_key/base_url).",
    )

    @field_validator("model", "display_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class LLMUpdate(BaseModel):
    """Payload to partially update a stored LLM. All fields optional.

    ``provider_connection_id`` may be changed to re-point the profile at a
    different connection. ``config`` replaces the blob wholesale when set.
    """

    model_config = ConfigDict(populate_by_name=True)

    provider_connection_id: uuid.UUID | None = None
    model: str | None = Field(default=None, min_length=1, max_length=255)
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None

    @field_validator("model", "display_name")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("must be a non-empty string")
        return v


class LLMRead(BaseModel):
    """Stored LLM profile representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    provider_connection_id: uuid.UUID
    model: str
    display_name: str
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class LLMSearchFilter(BaseSearchFilter[StoredLLM]):
    """Optional filter clauses for `GET /llms`."""

    model__contains: str | None = Field(
        default=None, description="Case-insensitive model substring."
    )
    display_name__contains: str | None = Field(
        default=None, description="Case-insensitive display name substring."
    )
    provider_connection_id__eq: uuid.UUID | None = Field(
        default=None, description="Exact provider connection id match."
    )
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class LLMSearchResult(BaseModel):
    """Paginated collection of stored LLM profiles."""

    items: list[LLMRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /llms/batch applies create/update/delete atomically
# (AGENTS.md §3). Operations reuse the single-item payloads; updates and
# deletes target a specific id.


class LLMBatchCreate(BaseModel):
    """Create operation within an LLM batch write."""

    op: Literal["create"] = "create"
    data: LLMCreate


class LLMBatchUpdate(BaseModel):
    """Update operation within an LLM batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: LLMUpdate


class LLMBatchDelete(BaseModel):
    """Delete operation within an LLM batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


LLMBatchOp = Annotated[
    LLMBatchCreate | LLMBatchUpdate | LLMBatchDelete,
    Field(discriminator="op"),
]


class LLMBatchWriteRequest(BaseModel):
    """Request body for `POST /llms/batch`."""

    operations: list[LLMBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/update/delete mixed.",
    )


# ---------------------------------------------------------------------- #
# Completion action
# ---------------------------------------------------------------------- #


class CompletionRequest(BaseModel):
    """Body for ``POST /llm/completion/{llm_id}``.

    The LLM profile to run is named by the path ``llm_id`` (the ``USE``
    permission is checked on that LLM). The provider connection is inferred
    from the LLM and used only to source credentials.

    ``messages`` are OpenHands SDK :class:`Message` dicts (role + content).
    Any ``params`` are forwarded as overrides to the SDK :class:`LLM.completion`
    call.
    """

    messages: list[dict[str, Any]] = Field(
        min_length=1,
        description="OpenHands SDK Message dicts (role + content).",
    )
    tools: list[dict[str, Any]] | None = Field(
        default=None,
        description="Optional OpenHands SDK ToolDefinition dicts.",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra kwargs forwarded to LLM.completion.",
    )


class CompletionResponse(BaseModel):
    """Result of a proxied completion.

    Mirrors the relevant fields of the SDK :class:`LLMResponse`: the assistant
    :class:`Message`, the token-usage :class:`MetricsSnapshot`, and the provider
    response id. The raw LiteLLM response is not returned (it is not JSON-safe).
    """

    id: str
    message: dict[str, Any]
    metrics: dict[str, Any]


# ---------------------------------------------------------------------- #
# Aggregated usage (read-only)
# ---------------------------------------------------------------------- #


class AggregatedUsageRead(BaseModel):
    """One per-minute, per-user rollup row, returned read-only by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    minute: datetime
    user_id: uuid.UUID
    invocations: int
    prompt_tokens: int
    completion_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int
    context_window: int
    per_turn_token: int
    accumulated_cost: float
    created_at: datetime
    updated_at: datetime


class AggregatedUsageSearchFilter(BaseSearchFilter[LlmAggregatedUsage]):
    """Optional filter clauses for `GET /llm/aggregated-usage`."""

    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    minute__gte: datetime | None = Field(default=None)
    minute__lt: datetime | None = Field(default=None)
    minute__gt: datetime | None = Field(default=None)
    minute__lte: datetime | None = Field(default=None)


class AggregatedUsageSearchResult(BaseModel):
    """Paginated collection of aggregated-usage rows."""

    items: list[AggregatedUsageRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


__all__ = [
    "AggregatedUsageRead",
    "AggregatedUsageSearchFilter",
    "AggregatedUsageSearchResult",
    "CompletionRequest",
    "CompletionResponse",
    "LLMBatchCreate",
    "LLMBatchDelete",
    "LLMBatchOp",
    "LLMBatchUpdate",
    "LLMBatchWriteRequest",
    "LLMCreate",
    "LLMRead",
    "LLMSearchFilter",
    "LLMSearchResult",
    "LLMUpdate",
    "ProviderConnectionBatchCreate",
    "ProviderConnectionBatchDelete",
    "ProviderConnectionBatchOp",
    "ProviderConnectionBatchUpdate",
    "ProviderConnectionBatchWriteRequest",
    "ProviderConnectionCreate",
    "ProviderConnectionRead",
    "ProviderConnectionSearchFilter",
    "ProviderConnectionSearchResult",
    "ProviderConnectionUpdate",
]
