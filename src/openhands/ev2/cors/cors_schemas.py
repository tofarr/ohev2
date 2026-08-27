"""Pydantic schemas for the global CORS allow-list feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/cors-origins`` with
cursor pagination; create is ``POST`` and remove is ``DELETE /{id}``. There is
no update — origins are immutable, delete and re-create.
"""

from __future__ import annotations

import uuid
from datetime import datetime

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
