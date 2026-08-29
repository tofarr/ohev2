"""Pydantic schemas for the CORS allow-list feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/cors-origins`` with
cursor pagination; create is ``POST`` and remove is ``DELETE /{id}``. There is
no update — origins are immutable, delete and re-create. The batch endpoints
(``GET /cors-origins/batch``, ``POST /cors-origins/batch``) follow §3: batch
read returns resources aligned to the requested ids; batch write applies
create/delete operations atomically (no update op, since origins are immutable).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class AllowedOriginCreate(BaseModel):
    """Payload to register a permitted browser origin."""

    origin: str = Field(
        description="Serialized browser origin (scheme://host[:port], RFC 6454).",
    )


class AllowedOriginRead(BaseModel):
    """Representation of a permitted origin returned by the API."""

    id: uuid.UUID
    origin: str
    created_at: datetime


class AllowedOriginSearchResult(BaseModel):
    """Paginated collection of permitted origins."""

    items: list[AllowedOriginRead]
    next_cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=100)


# Batch write: POST /cors-origins/batch applies create/delete atomically
# (AGENTS.md §3). Origins are immutable, so there is no update op; to change an
# origin, delete and re-create within the same batch.


class AllowedOriginBatchCreate(BaseModel):
    """Create operation within a CORS origin batch write."""

    op: Literal["create"] = "create"
    data: AllowedOriginCreate


class AllowedOriginBatchDelete(BaseModel):
    """Delete operation within a CORS origin batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


AllowedOriginBatchOp = Annotated[
    AllowedOriginBatchCreate | AllowedOriginBatchDelete,
    Field(discriminator="op"),
]


class AllowedOriginBatchWriteRequest(BaseModel):
    """Request body for `POST /cors-origins/batch`."""

    operations: list[AllowedOriginBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )


__all__ = [
    "AllowedOriginBatchWriteRequest",
    "AllowedOriginCreate",
    "AllowedOriginRead",
    "AllowedOriginSearchResult",
]
