"""Pydantic schemas for the DB-backed sandbox template resource.

Templates are mutable (unlike the prior image-inventory model): create, read,
update, and delete are all supported. The ``id`` is a UUID, not the image name,
so the ``docker_image_tag`` can change without orphaning foreign keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openhands.ev2.sandbox.sandbox_models import ExposedPort
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.util.search_filter import BaseSearchFilter

_MAX_ENV_VARS_CHARS = 4096
_MAX_META_CHARS = 4096
_MAX_EXPOSED_PORTS = 100


def _serialized_len(value: Any) -> int:
    import json

    return len(json.dumps(value, separators=(",", ":"), sort_keys=True))


class SandboxTemplateCreate(BaseModel):
    """Payload to create a sandbox template."""

    model_config = ConfigDict(populate_by_name=True)

    docker_image_tag: str = Field(min_length=1, max_length=1024)
    delete_after_idle_seconds: int | None = Field(default=None, gt=0)
    in_container_user_id: int | None = Field(default=None, ge=0)
    in_container_group_id: int | None = Field(default=None, ge=0)
    max_memory: int | None = Field(default=None, gt=0)
    exposed_ports: list[ExposedPort] = Field(default_factory=list, max_length=_MAX_EXPOSED_PORTS)
    env_vars: dict[str, str] = Field(default_factory=dict)
    working_dir: str = Field(default="/home/openhands", min_length=1, max_length=1024)
    snapshot_dirs: list[str] = Field(default_factory=list)
    snapshot_on_deactivate: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_size_limits(self) -> SandboxTemplateCreate:
        if _serialized_len(self.env_vars) > _MAX_ENV_VARS_CHARS:
            raise ValueError("env_vars must not exceed 4k characters when serialized.")
        if _serialized_len(self.meta) > _MAX_META_CHARS:
            raise ValueError("meta must not exceed 4k characters when serialized.")
        return self


class SandboxTemplateUpdate(BaseModel):
    """Partial update of a sandbox template.

    Every field is optional; only the fields present in the request body are
    applied. A ``None`` value for a nullable field explicitly clears it.
    """

    model_config = ConfigDict(populate_by_name=True)

    docker_image_tag: str | None = Field(default=None, min_length=1, max_length=1024)
    delete_after_idle_seconds: int | None = Field(default=None, gt=0)
    in_container_user_id: int | None = Field(default=None, ge=0)
    in_container_group_id: int | None = Field(default=None, ge=0)
    max_memory: int | None = Field(default=None, gt=0)
    exposed_ports: list[ExposedPort] | None = Field(default=None, max_length=_MAX_EXPOSED_PORTS)
    env_vars: dict[str, str] | None = None
    working_dir: str | None = Field(default=None, min_length=1, max_length=1024)
    snapshot_dirs: list[str] | None = None
    snapshot_on_deactivate: bool | None = None
    meta: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate_size_limits(self) -> SandboxTemplateUpdate:
        if self.env_vars is not None and _serialized_len(self.env_vars) > _MAX_ENV_VARS_CHARS:
            raise ValueError("env_vars must not exceed 4k characters when serialized.")
        if self.meta is not None and _serialized_len(self.meta) > _MAX_META_CHARS:
            raise ValueError("meta must not exceed 4k characters when serialized.")
        return self


class SandboxTemplateRead(BaseModel):
    """Sandbox template representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    docker_image_tag: str
    delete_after_idle_seconds: int | None
    in_container_user_id: int | None
    in_container_group_id: int | None
    max_memory: int | None
    exposed_ports: list[ExposedPort]
    env_vars: dict[str, str]
    working_dir: str
    snapshot_dirs: list[str]
    snapshot_on_deactivate: bool
    meta: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class SandboxTemplateSearchFilter(BaseSearchFilter[SandboxTemplate]):
    """Optional filters for ``GET /sandbox/sandbox-templates``."""

    docker_image_tag__contains: str | None = Field(default=None)
    docker_image_tag__eq: str | None = Field(default=None)
    working_dir__eq: str | None = Field(default=None)
    snapshot_on_deactivate__eq: bool | None = Field(default=None)
    creator_id__eq: uuid.UUID | None = Field(default=None)
    created_at__gte: datetime | None = Field(default=None)
    created_at__lt: datetime | None = Field(default=None)
    created_at__gt: datetime | None = Field(default=None)
    created_at__lte: datetime | None = Field(default=None)


class SandboxTemplateSearchResult(BaseModel):
    """Paginated collection of sandbox templates."""

    items: list[SandboxTemplateRead]
    next_cursor: str | None = Field(default=None)
    limit: int


class SandboxTemplateBatchCreate(BaseModel):
    """Create operation within a sandbox template batch write."""

    op: Literal["create"] = "create"
    data: SandboxTemplateCreate


class SandboxTemplateBatchUpdate(BaseModel):
    """Update operation within a sandbox template batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: SandboxTemplateUpdate


class SandboxTemplateBatchDelete(BaseModel):
    """Delete operation within a sandbox template batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


SandboxTemplateBatchOp = Annotated[
    SandboxTemplateBatchCreate | SandboxTemplateBatchUpdate | SandboxTemplateBatchDelete,
    Field(discriminator="op"),
]


class SandboxTemplateBatchWriteRequest(BaseModel):
    """Request body for ``POST /sandbox/sandbox-templates/batch``."""

    operations: list[SandboxTemplateBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Create/update/delete operations applied atomically in one transaction.",
    )
