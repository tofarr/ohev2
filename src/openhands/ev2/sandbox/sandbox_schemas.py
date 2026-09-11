"""Pydantic schemas for the sandbox feature.

The request/response surface is intentionally a faithful superset of the
existing sandbox-template schemas, adapted to the new template shape (an ``id``
that is the provider's identifier — a Docker image name — plus lifecycle knobs
``idle_pause_seconds``, ``paused_delete_seconds`` and ``max_age_seconds``).
``provider_kind`` is dropped because the service implementation is chosen by
configuration, not per-request, and each service owns its template variant.

Templates are functionally immutable (create and delete only); there is no
``SandboxTemplateUpdate`` schema and no update batch op. Sandboxes, by
contrast, expose a single mutable field — ``desired_status`` — which drives
pause/resume.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox.sandbox_models import (
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.util.search_filter import BaseSearchFilter

# --------------------------------------------------------------------------- #
# Sandboxes.
# --------------------------------------------------------------------------- #


class SandboxCreate(BaseModel):
    """Payload to create a sandbox.

    The sandbox is created from a template (``sandbox_template_id`` names the
    template id) and starts in the ``inactive`` desired state. The sandbox
    ``id`` is assigned by the sandbox service (the provider generates it —
    e.g. Docker mints a humorous container name), never supplied by the
    caller. Only ``desired_status`` is mutable after creation (via
    :class:`SandboxUpdate`).

    When ``snapshot_id`` is supplied, the provider restores the named
    snapshot's workspace contents into the new sandbox before starting it
    (analogous to creating a Kubernetes PVC from a VolumeSnapshot). The
    snapshot must exist and be in a ready state.
    """

    model_config = ConfigDict(populate_by_name=True)

    sandbox_template_id: str = Field(
        min_length=1, max_length=1024, description="Template id to instantiate."
    )
    snapshot_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description=(
            "Optional snapshot id whose workspace contents are restored into "
            "the new sandbox before it starts."
        ),
    )


class SandboxUpdate(BaseModel):
    """Payload to partially update a sandbox.

    The only mutable field is ``desired_status``; setting it drives
    pause/resume (``active``/``inactive``) on the backing container.
    """

    model_config = ConfigDict(populate_by_name=True)

    desired_status: SandboxStatus


class SandboxRead(BaseModel):
    """Sandbox representation returned by the public API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    sandbox_template_id: str
    status: SandboxStatus
    desired_status: SandboxStatus
    snapshot_mode: SnapshotMode
    session_api_key: str | None
    exposed_urls: list[ExposedUrl]
    created_at: datetime
    last_accessed_at: datetime | None
    status_detail: str | None
    volume_mounts: list[VolumeMount]
    user_id: uuid.UUID | None


class SandboxSearchFilter(BaseSearchFilter[Sandbox]):
    """Optional filters for ``GET /sandbox/sandboxes``."""

    id__contains: str | None = Field(default=None, description="Case-insensitive id substring.")
    id__eq: str | None = Field(default=None, description="Exact id match.")
    sandbox_template_id__eq: str | None = Field(
        default=None, description="Exact template id match."
    )
    status__eq: SandboxStatus | None = Field(default=None)
    desired_status__eq: SandboxStatus | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)
    last_accessed_at__gte: datetime | None = Field(default=None)
    last_accessed_at__lt: datetime | None = Field(default=None)
    last_accessed_at__gt: datetime | None = Field(default=None)
    last_accessed_at__lte: datetime | None = Field(default=None)


class SandboxSearchResult(BaseModel):
    """Paginated collection of sandboxes."""

    items: list[SandboxRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class SandboxBatchCreate(BaseModel):
    """Create operation within a sandbox batch write."""

    op: Literal["create"] = "create"
    data: SandboxCreate


class SandboxBatchDelete(BaseModel):
    """Delete operation within a sandbox batch write."""

    op: Literal["delete"] = "delete"
    id: str


SandboxBatchOp = Annotated[
    SandboxBatchCreate | SandboxBatchDelete,
    Field(discriminator="op"),
]


class SandboxBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox/sandboxes/batch``."""

    operations: list[SandboxBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )
