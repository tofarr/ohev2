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

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openhands.ev2.sandbox.sandbox_models import (
    ExposedPort,
    ExposedUrl,
    Sandbox,
    SandboxSnapshot,
    SandboxStatus,
    SandboxTemplate,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.util.search_filter import BaseSearchFilter


class SandboxTemplateCreate(BaseModel):
    """Payload to create a sandbox template."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(min_length=1, max_length=1024)
    command: list[str] | None = None
    initial_env: dict[str, str] = Field(
        default_factory=dict, description="Initial Environment Variables"
    )
    working_dir: str = "/home/openhands/workspace"
    idle_pause_seconds: int | None = Field(default=None, gt=0)
    paused_delete_seconds: int | None = Field(default=None, gt=0)
    max_age_seconds: int | None = Field(default=None, gt=0)
    max_memory: int | None = Field(default=None, gt=0)
    exposed_ports: list[ExposedPort] = Field(default_factory=list)
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.UNSUPPORTED,
        description="Snapshot strategy supported by sandboxes built from this template.",
    )


class SandboxTemplateRead(BaseModel):
    """Sandbox template representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    command: list[str] | None
    initial_env: dict[str, str]
    working_dir: str
    idle_pause_seconds: int | None
    paused_delete_seconds: int | None
    max_age_seconds: int | None
    max_memory: int | None
    exposed_ports: list[ExposedPort]
    snapshot_mode: SnapshotMode
    created_at: datetime
    user_id: uuid.UUID | None


class SandboxTemplateSearchFilter(BaseSearchFilter[SandboxTemplate]):
    """Optional filters for ``GET /sandbox/sandbox-templates``."""

    id__contains: str | None = Field(default=None, description="Case-insensitive id substring.")
    id__eq: str | None = Field(default=None, description="Exact id match.")
    working_dir__eq: str | None = Field(default=None, description="Exact working_dir match.")
    idle_pause_seconds__eq: int | None = Field(default=None)
    paused_delete_seconds__eq: int | None = Field(default=None)
    max_age_seconds__eq: int | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxTemplateSearchResult(BaseModel):
    """Paginated collection of sandbox templates."""

    items: list[SandboxTemplateRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class SandboxTemplateBatchCreate(BaseModel):
    """Create operation within a sandbox template batch write."""

    op: Literal["create"] = "create"
    data: SandboxTemplateCreate


class SandboxTemplateBatchDelete(BaseModel):
    """Delete operation within a sandbox template batch write."""

    op: Literal["delete"] = "delete"
    id: str


SandboxTemplateBatchOp = Annotated[
    SandboxTemplateBatchCreate | SandboxTemplateBatchDelete,
    Field(discriminator="op"),
]


class SandboxTemplateBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox/sandbox-templates/batch``."""

    operations: list[SandboxTemplateBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )


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
    """

    model_config = ConfigDict(populate_by_name=True)

    sandbox_template_id: str = Field(
        min_length=1, max_length=1024, description="Template id to instantiate."
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


# --------------------------------------------------------------------------- #
# Sandbox snapshots.
# --------------------------------------------------------------------------- #


class SandboxSnapshotCreate(BaseModel):
    """Payload to create a sandbox snapshot.

    Exactly one source is supplied: ``sandbox_id`` snapshots an existing
    sandbox, while ``file`` (handled by the router as a multipart upload)
    together with ``schema_type`` imports a snapshot from an uploaded artifact.
    The service receives already-read file bytes via ``file_data`` when a file
    import is requested.

    The snapshot ``id`` is assigned by the sandbox service implementation (the
    provider generates it), never supplied by the caller — mirroring how
    :class:`SandboxCreate` delegates id generation to the provider.
    """

    model_config = ConfigDict(populate_by_name=True)

    sandbox_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Sandbox id to snapshot. Mutually exclusive with file import.",
    )
    schema_type: str | None = Field(
        default=None,
        max_length=255,
        description="Schema type of an uploaded snapshot file (e.g. ``docker-image-tar``).",
    )
    file_data: bytes | None = Field(
        default=None,
        description="Raw bytes of an uploaded snapshot file; set by the router, not by callers.",
    )

    @model_validator(mode="after")
    def _validate_exclusive_source(self) -> SandboxSnapshotCreate:
        if self.sandbox_id is not None and self.file_data is not None:
            raise ValueError("sandbox_id and file are mutually exclusive.")
        if self.sandbox_id is None and self.file_data is None:
            raise ValueError("Either sandbox_id or a file upload is required.")
        if self.file_data is not None and not self.schema_type:
            raise ValueError("schema_type is required when importing a file.")
        return self


class SandboxSnapshotRead(BaseModel):
    """Sandbox snapshot representation returned by the public API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    download_url: str | None
    image_id: str | None = None
    sandbox_id: str | None = None
    user_id: uuid.UUID | None = None


class SandboxSnapshotSearchFilter(BaseSearchFilter[SandboxSnapshot]):
    """Optional filters for ``GET /sandbox/sandbox-snapshots``."""

    id__contains: str | None = Field(default=None, description="Case-insensitive id substring.")
    id__eq: str | None = Field(default=None, description="Exact id match.")
    sandbox_id__eq: str | None = Field(default=None, description="Exact source sandbox id match.")
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxSnapshotSearchResult(BaseModel):
    """Paginated collection of sandbox snapshots."""

    items: list[SandboxSnapshotRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


class SandboxSnapshotBatchDelete(BaseModel):
    """Delete operation within a snapshot batch write."""

    op: Literal["delete"] = "delete"
    id: str


SandboxSnapshotBatchOp = Annotated[
    SandboxSnapshotBatchDelete,
    Field(discriminator="op"),
]


class SandboxSnapshotBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox/sandbox-snapshots/batch``.

    Snapshots are created through the multipart create endpoint (a file may be
    involved), so the batch write supports delete operations only.
    """

    operations: list[SandboxSnapshotBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Delete operations to apply atomically.",
    )
