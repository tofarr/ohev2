"""Pydantic schemas for the DB-backed sandbox config resource.

A :class:`SandboxConfig` is the durable intent for a sandbox. The only mutable
fields are ``enabled``, ``expires_at``, ``sandbox_snapshot_id``,
``snapshot_on_deactivate``, and ``meta``. The ``session_api_key`` is never
exposed in the API read (it is encrypted at rest and revealed only to the live
sandbox service).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.util.search_filter import BaseSearchFilter


class SandboxConfigCreate(BaseModel):
    """Payload to create a sandbox config.

    Creates the durable intent for a sandbox. When ``enabled`` is ``True`` the
    sandbox service reconciles by booting the live sandbox (restoring from
    ``sandbox_snapshot_id`` when set). Defaults to ``enabled=False`` so the
    caller explicitly opts in.
    """

    model_config = ConfigDict(populate_by_name=True)

    sandbox_template_id: uuid.UUID = Field(description="Template to instantiate.")
    sandbox_snapshot_id: uuid.UUID | None = Field(
        default=None,
        description="Optional snapshot to restore when (re)creating the live sandbox.",
    )
    enabled: bool = Field(
        default=False,
        description="Whether the live sandbox should be running.",
    )
    snapshot_on_deactivate: bool | None = Field(
        default=None,
        description="Read from the template when not explicitly set.",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Optional expiry; the lifecycle sweep refreshes this from the template.",
    )
    meta: dict[str, Any] = Field(default_factory=dict)


class SandboxConfigUpdate(BaseModel):
    """Partial update of a sandbox config.

    Only the mutable intent fields may be patched; ``sandbox_template_id`` and
    ``session_api_key`` are immutable after creation.
    """

    model_config = ConfigDict(populate_by_name=True)

    enabled: bool | None = None
    sandbox_snapshot_id: uuid.UUID | None = None
    snapshot_on_deactivate: bool | None = None
    expires_at: datetime | None = None
    meta: dict[str, Any] | None = None


class SandboxConfigRead(BaseModel):
    """Sandbox config representation returned by the API.

    The ``session_api_key`` is intentionally omitted — it is encrypted at rest
    and revealed only to the sandbox service.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    sandbox_template_id: uuid.UUID
    enabled: bool
    sandbox_snapshot_id: uuid.UUID | None
    expires_at: datetime | None
    snapshot_on_deactivate: bool
    meta: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class SandboxConfigSearchFilter(BaseSearchFilter[SandboxConfig]):
    """Optional filters for ``GET /sandbox/sandbox-configs``."""

    sandbox_template_id__eq: uuid.UUID | None = Field(default=None)
    enabled__eq: bool | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    expires_at__gte: datetime | None = Field(default=None)
    expires_at__lt: datetime | None = Field(default=None)
    expires_at__gt: datetime | None = Field(default=None)
    expires_at__lte: datetime | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxConfigSearchResult(BaseModel):
    """Paginated collection of sandbox configs."""

    items: list[SandboxConfigRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class SandboxConfigBatchCreate(BaseModel):
    """Create operation within a sandbox config batch write."""

    op: Literal["create"] = "create"
    data: SandboxConfigCreate


class SandboxConfigBatchUpdate(BaseModel):
    """Update operation within a sandbox config batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SandboxConfigUpdate


class SandboxConfigBatchDelete(BaseModel):
    """Delete operation within a sandbox config batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SandboxConfigBatchOp = Annotated[
    SandboxConfigBatchCreate | SandboxConfigBatchUpdate | SandboxConfigBatchDelete,
    Field(discriminator="op"),
]


class SandboxConfigBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox/sandbox-configs/batch``."""

    operations: list[SandboxConfigBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Create/update/delete operations applied atomically in one transaction.",
    )
