"""Pydantic schemas for the DB-backed sandbox snapshot resource.

Snapshots are create/read/delete only (no update). The create endpoint accepts
a multipart form (a snapshot may be imported from an uploaded file). The
artifact storage is hidden inside the sandbox service; the DB row is the index.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openhands.ev2.sandbox.sandbox_snapshot_models import SandboxSnapshot
from openhands.ev2.util.search_filter import BaseSearchFilter


class SandboxSnapshotCreate(BaseModel):
    """Payload to create a sandbox snapshot.

    Exactly one source is supplied: ``sandbox_id`` snapshots an existing
    sandbox, while ``file_data`` (set by the router from a multipart upload)
    together with ``schema_type`` imports a snapshot from an uploaded artifact.
    """

    model_config = ConfigDict(populate_by_name=True)

    sandbox_template_id: uuid.UUID = Field(
        description="Template the snapshot is scoped to (for restore compatibility).",
    )
    sandbox_id: str | None = Field(
        default=None,
        description="Source sandbox id (container name) to snapshot. Mutually exclusive with file import.",
    )
    schema_type: str | None = Field(
        default=None,
        max_length=255,
        description="Schema type of an uploaded snapshot file (e.g. docker-workspace-tar-v1).",
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
    """Sandbox snapshot representation returned by the API."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    sandbox_template_id: uuid.UUID
    sandbox_id: str | None
    schema_type: str = Field(
        alias="schema",
        description="Compatibility tag (e.g. docker-workspace-tar-v1).",
    )
    download_url: str
    size_bytes: int | None
    created_at: datetime


class SandboxSnapshotSearchFilter(BaseSearchFilter[SandboxSnapshot]):
    """Optional filters for ``GET /sandbox/sandbox-snapshots``."""

    sandbox_template_id__eq: uuid.UUID | None = Field(default=None)
    sandbox_id__eq: str | None = Field(default=None)
    schema__eq: str | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxSnapshotSearchResult(BaseModel):
    """Paginated collection of sandbox snapshots."""

    items: list[SandboxSnapshotRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class SandboxSnapshotBatchDelete(BaseModel):
    """Delete operation within a snapshot batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


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
