"""Pydantic schemas for sandbox templates, sandboxes, and snapshots."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplateSpec,
    FuseySandboxSnapshotArtifact,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerSpec,
    Sandbox,
    SandboxFilesystem,
    SandboxFilesystemStatus,
    SandboxProviderKind,
    SandboxServerSpec,
    SandboxSnapshot,
    SandboxSnapshotStatus,
    SandboxStatus,
    SandboxStorageKind,
    SandboxStorageSpec,
    SandboxTemplate,
    SandboxTemplateSpec,
)
from openhands.ev2.util.search_filter import BaseSearchFilter


class ExposedSandboxUrl(BaseModel):
    """Public URL exposed by an active sandbox."""

    name: str = Field(min_length=1, max_length=64)
    url: str = Field(min_length=1, max_length=2048)
    protocol: Literal["http", "tcp"] = "http"


class SandboxTemplateCreate(BaseModel):
    """Payload to create a sandbox template."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    provider_kind: SandboxProviderKind = SandboxProviderKind.DOCKER
    template_spec: SandboxTemplateSpec
    server_spec: SandboxServerSpec = Field(default_factory=OpenHandsAgentServerSpec)
    storage_spec: SandboxStorageSpec = Field(default_factory=FuseySandboxStorageSpec)
    description: str | None = Field(default=None, max_length=4096)
    idle_timeout_seconds: int | None = Field(default=None, gt=0)
    max_lifetime_seconds: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _validate_kinds(self) -> SandboxTemplateCreate:
        if self.provider_kind != SandboxProviderKind.DOCKER:
            raise ValueError("only the docker sandbox provider is supported initially")
        if not isinstance(self.template_spec, DockerSandboxTemplateSpec):
            raise ValueError(
                "template_spec must be DockerSandboxTemplateSpec for provider_kind=docker"
            )
        if not isinstance(self.storage_spec, FuseySandboxStorageSpec):
            raise ValueError("only FuseySandboxStorageSpec is supported initially")
        return self


class SandboxTemplateUpdate(BaseModel):
    """Payload to partially update a sandbox template."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    template_spec: SandboxTemplateSpec | None = None
    server_spec: SandboxServerSpec | None = None
    storage_spec: SandboxStorageSpec | None = None
    description: str | None = Field(default=None, max_length=4096)
    idle_timeout_seconds: int | None = Field(default=None, gt=0)
    max_lifetime_seconds: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _validate_specs(self) -> SandboxTemplateUpdate:
        if self.template_spec is not None and not isinstance(
            self.template_spec, DockerSandboxTemplateSpec
        ):
            raise ValueError("only DockerSandboxTemplateSpec is supported initially")
        if self.storage_spec is not None and not isinstance(
            self.storage_spec, FuseySandboxStorageSpec
        ):
            raise ValueError("only FuseySandboxStorageSpec is supported initially")
        return self


class SandboxTemplateRead(BaseModel):
    """Sandbox template representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    provider_kind: SandboxProviderKind
    template_spec: SandboxTemplateSpec
    server_spec: SandboxServerSpec
    storage_spec: SandboxStorageSpec
    user_id: uuid.UUID
    description: str | None
    idle_timeout_seconds: int | None
    max_lifetime_seconds: int | None
    created_at: datetime
    updated_at: datetime


class SandboxTemplateSearchFilter(BaseSearchFilter[SandboxTemplate]):
    """Optional filters for ``GET /sandbox-templates``."""

    name__contains: str | None = Field(default=None)
    provider_kind__eq: SandboxProviderKind | None = Field(default=None)
    user_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxTemplateSearchResult(BaseModel):
    """Paginated collection of sandbox templates."""

    items: list[SandboxTemplateRead]
    next_cursor: str | None = None
    limit: int


class SandboxTemplateBatchCreate(BaseModel):
    """Create operation within a sandbox template batch."""

    op: Literal["create"] = "create"
    data: SandboxTemplateCreate


class SandboxTemplateBatchUpdate(BaseModel):
    """Update operation within a sandbox template batch."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SandboxTemplateUpdate


class SandboxTemplateBatchDelete(BaseModel):
    """Delete operation within a sandbox template batch."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SandboxTemplateBatchOp = Annotated[
    SandboxTemplateBatchCreate | SandboxTemplateBatchUpdate | SandboxTemplateBatchDelete,
    Field(discriminator="op"),
]


class SandboxTemplateBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox-templates/batch``."""

    operations: list[SandboxTemplateBatchOp] = Field(min_length=1, max_length=100)


class SandboxCreate(BaseModel):
    """Payload to create a durable sandbox in the inactive state."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    template_id: uuid.UUID
    filesystem_id: uuid.UUID | None = None
    snapshot_id: uuid.UUID | None = None
    description: str | None = Field(default=None, max_length=4096)
    idle_timeout_seconds: int | None = Field(default=None, gt=0)
    max_lifetime_seconds: int | None = Field(default=None, gt=0)


class SandboxUpdate(BaseModel):
    """Payload to partially update sandbox metadata."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    idle_timeout_seconds: int | None = Field(default=None, gt=0)
    max_lifetime_seconds: int | None = Field(default=None, gt=0)


class SandboxRead(BaseModel):
    """Sandbox representation returned by the public API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    template_id: uuid.UUID
    filesystem_id: uuid.UUID
    current_snapshot_id: uuid.UUID | None
    provider_kind: SandboxProviderKind
    status: SandboxStatus
    status_reason: str | None
    exposed_urls: list[ExposedSandboxUrl]
    description: str | None
    idle_timeout_seconds: int | None
    max_lifetime_seconds: int | None
    user_id: uuid.UUID
    last_activity_at: datetime | None
    last_activated_at: datetime | None
    last_deactivated_at: datetime | None
    delete_started_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SandboxSearchFilter(BaseSearchFilter[Sandbox]):
    """Optional filters for ``GET /sandboxes``."""

    name__contains: str | None = Field(default=None)
    provider_kind__eq: SandboxProviderKind | None = Field(default=None)
    status__eq: SandboxStatus | None = Field(default=None)
    template_id__eq: uuid.UUID | None = Field(default=None)
    filesystem_id__eq: uuid.UUID | None = Field(default=None)
    user_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxSearchResult(BaseModel):
    """Paginated collection of sandboxes."""

    items: list[SandboxRead]
    next_cursor: str | None = None
    limit: int


class SandboxBatchCreate(BaseModel):
    """Create operation within a sandbox batch."""

    op: Literal["create"] = "create"
    data: SandboxCreate


class SandboxBatchUpdate(BaseModel):
    """Update operation within a sandbox batch."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SandboxUpdate


class SandboxBatchDelete(BaseModel):
    """Delete operation within a sandbox batch."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SandboxBatchOp = Annotated[
    SandboxBatchCreate | SandboxBatchUpdate | SandboxBatchDelete,
    Field(discriminator="op"),
]


class SandboxBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandboxes/batch``."""

    operations: list[SandboxBatchOp] = Field(min_length=1, max_length=100)


class SandboxSnapshotCreate(BaseModel):
    """Payload to create a named Fusey generation snapshot from a sandbox."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    source_sandbox_id: uuid.UUID
    description: str | None = Field(default=None, max_length=4096)
    generation: str | None = Field(default=None, min_length=1, max_length=255)
    expires_at: datetime | None = None


class SandboxSnapshotUpdate(BaseModel):
    """Payload to partially update snapshot metadata."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    expires_at: datetime | None = None


class SandboxSnapshotRead(BaseModel):
    """Sandbox snapshot representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    filesystem_id: uuid.UUID
    source_sandbox_id: uuid.UUID | None
    storage_kind: SandboxStorageKind
    status: SandboxSnapshotStatus
    generation: str
    snapshot_artifact: FuseySandboxSnapshotArtifact
    user_id: uuid.UUID
    description: str | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SandboxSnapshotSearchFilter(BaseSearchFilter[SandboxSnapshot]):
    """Optional filters for ``GET /sandbox-snapshots``."""

    name__contains: str | None = Field(default=None)
    filesystem_id__eq: uuid.UUID | None = Field(default=None)
    source_sandbox_id__eq: uuid.UUID | None = Field(default=None)
    storage_kind__eq: SandboxStorageKind | None = Field(default=None)
    status__eq: SandboxSnapshotStatus | None = Field(default=None)
    user_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxSnapshotSearchResult(BaseModel):
    """Paginated collection of sandbox snapshots."""

    items: list[SandboxSnapshotRead]
    next_cursor: str | None = None
    limit: int


class SandboxSnapshotBatchCreate(BaseModel):
    """Create operation within a snapshot batch."""

    op: Literal["create"] = "create"
    data: SandboxSnapshotCreate


class SandboxSnapshotBatchUpdate(BaseModel):
    """Update operation within a snapshot batch."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SandboxSnapshotUpdate


class SandboxSnapshotBatchDelete(BaseModel):
    """Delete operation within a snapshot batch."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SandboxSnapshotBatchOp = Annotated[
    SandboxSnapshotBatchCreate | SandboxSnapshotBatchUpdate | SandboxSnapshotBatchDelete,
    Field(discriminator="op"),
]


class SandboxSnapshotBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox-snapshots/batch``."""

    operations: list[SandboxSnapshotBatchOp] = Field(min_length=1, max_length=100)


class SandboxFilesystemSearchFilter(BaseSearchFilter[SandboxFilesystem]):
    """Internal filesystem filter type used by services."""

    storage_kind__eq: SandboxStorageKind | None = Field(default=None)
    status__eq: SandboxFilesystemStatus | None = Field(default=None)
    user_id__eq: uuid.UUID | None = Field(default=None)


__all__ = [
    "DockerSandboxTemplateSpec",
    "FuseySandboxStorageSpec",
    "OpenHandsAgentServerSpec",
    "SandboxBatchWriteRequest",
    "SandboxCreate",
    "SandboxRead",
    "SandboxSearchFilter",
    "SandboxSearchResult",
    "SandboxSnapshotBatchWriteRequest",
    "SandboxSnapshotCreate",
    "SandboxSnapshotRead",
    "SandboxSnapshotSearchFilter",
    "SandboxSnapshotSearchResult",
    "SandboxSnapshotUpdate",
    "SandboxTemplateBatchWriteRequest",
    "SandboxTemplateCreate",
    "SandboxTemplateRead",
    "SandboxTemplateSearchFilter",
    "SandboxTemplateSearchResult",
    "SandboxTemplateUpdate",
    "SandboxUpdate",
]
