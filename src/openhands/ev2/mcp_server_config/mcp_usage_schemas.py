"""Pydantic schemas for the MCP aggregated-usage projection (read-only).

Mirrors the LLM aggregated-usage REST surface. The raw ``mcp_usage`` table is
not exposed over REST; usage queries go through the ``mcp_aggregated_usage``
projection served at ``/mcp-server-configs/aggregated-usage``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.mcp_server_config.mcp_usage_models import McpAggregatedUsage
from openhands.ev2.util.search_filter import BaseSearchFilter


class McpAggregatedUsageRead(BaseModel):
    """One per-minute, per-user rollup row, returned read-only by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    minute: datetime
    user_id: uuid.UUID
    invocations: int
    total_duration_ms: int
    created_at: datetime
    updated_at: datetime


class McpAggregatedUsageSearchFilter(BaseSearchFilter[McpAggregatedUsage]):
    """Optional filter clauses for `GET /mcp-server-configs/aggregated-usage`."""

    user_id__eq: uuid.UUID | None = Field(default=None, description="Exact user id match.")
    minute__gte: datetime | None = Field(default=None)
    minute__lt: datetime | None = Field(default=None)
    minute__gt: datetime | None = Field(default=None)
    minute__lte: datetime | None = Field(default=None)


class McpAggregatedUsageSearchResult(BaseModel):
    """Paginated collection of MCP aggregated-usage rows."""

    items: list[McpAggregatedUsageRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int
