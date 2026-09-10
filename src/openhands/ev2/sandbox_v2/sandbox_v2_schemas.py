"""Pydantic schemas for the sandbox_v2 feature.

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

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandbox,
    DockerSandboxTemplate,
    ExposedPort,
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SandboxTemplate,
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
    created_at: datetime


class SandboxTemplateSearchFilter(BaseSearchFilter[SandboxTemplate]):
    """Optional filters for ``GET /sandbox_v2/sandbox-templates``."""

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
    """Request body for ``POST /sandbox_v2/sandbox-templates/batch``."""

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

    The sandbox is created from a template (``sandbox_spec_id`` names the
    template id) and starts in the ``inactive`` desired state. Only
    ``desired_status`` is mutable after creation (via :class:`SandboxUpdate`).
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(min_length=1, max_length=255, description="Caller-chosen sandbox id.")
    sandbox_spec_id: str = Field(
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
    sandbox_spec_id: str
    status: SandboxStatus
    desired_status: SandboxStatus
    session_api_key: str | None
    exposed_urls: list[ExposedUrl]
    created_at: datetime
    status_detail: str | None
    volume_mounts: list[VolumeMount]


class SandboxSearchFilter(BaseSearchFilter[Sandbox]):
    """Optional filters for ``GET /sandbox_v2/sandboxes``."""

    id__contains: str | None = Field(default=None, description="Case-insensitive id substring.")
    id__eq: str | None = Field(default=None, description="Exact id match.")
    sandbox_spec_id__eq: str | None = Field(default=None, description="Exact template id match.")
    status__eq: SandboxStatus | None = Field(default=None)
    desired_status__eq: SandboxStatus | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


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
    """Request body for ``POST /sandbox_v2/sandboxes/batch``."""

    operations: list[SandboxBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Operations to apply atomically; create/delete mixed (no update).",
    )


__all__ = [
    "DockerSandbox",
    "DockerSandboxTemplate",
    "Sandbox",
    "SandboxBatchCreate",
    "SandboxBatchDelete",
    "SandboxBatchWriteRequest",
    "SandboxCreate",
    "SandboxRead",
    "SandboxSearchFilter",
    "SandboxSearchResult",
    "SandboxStatus",
    "SandboxTemplate",
    "SandboxTemplateBatchCreate",
    "SandboxTemplateBatchDelete",
    "SandboxTemplateBatchWriteRequest",
    "SandboxTemplateCreate",
    "SandboxTemplateRead",
    "SandboxTemplateSearchFilter",
    "SandboxTemplateSearchResult",
    "SandboxUpdate",
]
