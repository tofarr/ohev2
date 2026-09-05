"""ORM models and polymorphic types for sandbox resources.

The public sandbox resource represents durable user state. Compute is a
replaceable internal attachment, while persisted files live in a Fusey-backed
filesystem. Provider-specific and storage-specific payloads use the SDK
``DiscriminatedUnionMixin`` to match the rest of the codebase's polymorphism
pattern.
"""

from __future__ import annotations

import enum
import uuid
from abc import ABC
from datetime import datetime
from typing import Any, Literal, TypeVar

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from openhands.ev2.db import Base
from openhands.ev2.user.user_models import User

_TZ = DateTime(timezone=True)
_T = TypeVar("_T", bound=DiscriminatedUnionMixin)


class DiscriminatedUnionJSON(TypeDecorator[_T | None]):
    """Persist a SDK discriminated-union model as JSONB."""

    impl = JSONB
    cache_ok = True

    def __init__(self, union_base: type[_T]) -> None:
        super().__init__()
        self._union_base = union_base

    def process_bind_param(
        self,
        value: DiscriminatedUnionMixin | dict[str, Any] | None,
        dialect: Any,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        return value.model_dump(mode="json")

    def process_result_value(
        self,
        value: dict[str, Any] | None,
        dialect: Any,
    ) -> _T | None:
        if value is None:
            return None
        return self._union_base.model_validate(value)


class SandboxProviderKind(enum.StrEnum):
    """Compute provider kinds supported by the sandbox control plane."""

    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    E2B = "e2b"


class SandboxStorageKind(enum.StrEnum):
    """Persistent storage implementations for sandbox filesystems."""

    FUSEY = "fusey"


class SandboxStatus(enum.StrEnum):
    """Provider-neutral public sandbox lifecycle states."""

    INACTIVE = "inactive"
    ACTIVATING = "activating"
    ACTIVE = "active"
    DEACTIVATING = "deactivating"
    DELETING = "deleting"
    ERROR = "error"


class SandboxFilesystemStatus(enum.StrEnum):
    """Lifecycle states for Fusey-backed durable filesystems."""

    READY = "ready"
    MOUNTED = "mounted"
    DELETING = "deleting"
    ERROR = "error"


class SandboxSnapshotStatus(enum.StrEnum):
    """Lifecycle states for named Fusey generation pins."""

    CREATING = "creating"
    READY = "ready"
    DELETING = "deleting"
    ERROR = "error"


class SandboxComputeStatus(enum.StrEnum):
    """Internal lifecycle states for replaceable compute attachments."""

    WARMING = "warming"
    DORMANT = "dormant"
    CLAIMED = "claimed"
    MOUNTING = "mounting"
    INITIALIZING = "initializing"
    SERVING = "serving"
    DRAINING = "draining"
    RELEASED = "released"
    FAILED = "failed"
    DELETED = "deleted"


class SandboxPortSpec(BaseModel):
    """A user-visible service port exposed by a sandbox runtime."""

    name: str = Field(min_length=1, max_length=64)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["http", "tcp"] = "http"


class SandboxResourceLimits(BaseModel):
    """Portable resource caps for sandbox compute."""

    cpu_cores: float | None = Field(default=None, gt=0)
    memory_mb: int | None = Field(default=None, gt=0)
    disk_mb: int | None = Field(default=None, gt=0)


class SandboxTemplateSpec(DiscriminatedUnionMixin, ABC):
    """Base class for provider-specific sandbox template definitions."""


class DockerSandboxTemplateSpec(SandboxTemplateSpec):
    """Docker-specific compute definition for a sandbox template."""

    provider_kind: Literal["docker"] = "docker"
    image: str = Field(min_length=1, max_length=1024)
    command: list[str] | None = None
    working_dir: str | None = Field(default=None, max_length=1024)
    ports: list[SandboxPortSpec] = Field(default_factory=list, max_length=32)
    resources: SandboxResourceLimits = Field(default_factory=SandboxResourceLimits)


class SandboxServerSpec(DiscriminatedUnionMixin, ABC):
    """Base class for server protocols hosted inside sandbox compute."""


class OpenHandsAgentServerSpec(SandboxServerSpec):
    """Configuration for the openhands-agent-server process in a sandbox."""

    server_kind: Literal["openhands_agent_server"] = "openhands_agent_server"
    internal_port: int = Field(default=18000, ge=1, le=65535)
    health_path: str = Field(default="/health", min_length=1, max_length=255)
    init_path: str = Field(default="/init", min_length=1, max_length=255)
    files_path: str = Field(default="/files", min_length=1, max_length=255)


class SandboxStorageSpec(DiscriminatedUnionMixin, ABC):
    """Base class for persisted sandbox filesystem definitions."""


class FuseySandboxStorageSpec(SandboxStorageSpec):
    """Fusey-backed filesystem mounted into sandbox compute."""

    storage_kind: Literal["fusey"] = "fusey"
    mount_path: str = Field(default="/workspace", min_length=1, max_length=1024)
    max_size_bytes: int | None = Field(default=None, gt=0)
    persist_interval_seconds: int | None = Field(default=None, gt=0)

    @field_validator("mount_path")
    @classmethod
    def _absolute_mount_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("mount_path must be absolute")
        return value.rstrip("/") or "/"


class SandboxRuntimeState(DiscriminatedUnionMixin, ABC):
    """Base class for provider runtime handles stored on internal compute rows."""


class DockerSandboxRuntimeState(SandboxRuntimeState):
    """Docker runtime handle for an internal compute attachment."""

    provider_kind: Literal["docker"] = "docker"
    container_id: str = Field(min_length=1, max_length=255)
    internal_url: str | None = Field(default=None, max_length=2048)


class SandboxServerState(DiscriminatedUnionMixin, ABC):
    """Base class for sandbox server observations."""


class OpenHandsAgentServerState(SandboxServerState):
    """Observed state for an openhands-agent-server process."""

    server_kind: Literal["openhands_agent_server"] = "openhands_agent_server"
    base_url: str | None = Field(default=None, max_length=2048)
    initialized: bool = False
    healthy: bool = False


class SandboxSnapshotArtifact(DiscriminatedUnionMixin, ABC):
    """Base class for storage-specific snapshot artifact references."""


class FuseySandboxSnapshotArtifact(SandboxSnapshotArtifact):
    """A named pin of a Fusey filesystem generation."""

    storage_kind: Literal["fusey"] = "fusey"
    filesystem_id: uuid.UUID
    generation: str = Field(min_length=1, max_length=255)
    index_object_key: str | None = Field(default=None, max_length=2048)


class SandboxTemplate(Base):
    """Reusable template describing how to activate a sandbox."""

    __tablename__ = "sandbox_templates"
    __table_args__ = {"comment": "Reusable sandbox activation templates"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider_kind: Mapped[SandboxProviderKind] = mapped_column(String(32), index=True)
    template_spec: Mapped[SandboxTemplateSpec] = mapped_column(
        DiscriminatedUnionJSON(SandboxTemplateSpec),
    )
    server_spec: Mapped[SandboxServerSpec] = mapped_column(
        DiscriminatedUnionJSON(SandboxServerSpec),
    )
    storage_spec: Mapped[SandboxStorageSpec] = mapped_column(
        DiscriminatedUnionJSON(SandboxStorageSpec),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    idle_timeout_seconds: Mapped[int | None] = mapped_column(default=None, nullable=True)
    max_lifetime_seconds: Mapped[int | None] = mapped_column(default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TZ, init=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped[User] = relationship(init=False, lazy="selectin")


class SandboxFilesystem(Base):
    """Durable Fusey-backed filesystem for sandbox files."""

    __tablename__ = "sandbox_filesystems"
    __table_args__ = {"comment": "Durable Fusey-backed sandbox filesystems"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    storage_kind: Mapped[SandboxStorageKind] = mapped_column(String(32), index=True)
    object_prefix: Mapped[str] = mapped_column(String(2048), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[SandboxFilesystemStatus] = mapped_column(
        String(32),
        default=SandboxFilesystemStatus.READY,
        server_default=SandboxFilesystemStatus.READY.value,
        index=True,
    )
    head_generation: Mapped[str | None] = mapped_column(String(255), default=None, nullable=True)
    mount_path_default: Mapped[str] = mapped_column(String(1024), default="/workspace")
    max_size_bytes: Mapped[int | None] = mapped_column(BigInteger, default=None, nullable=True)
    size_bytes_estimate: Mapped[int | None] = mapped_column(BigInteger, default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TZ, init=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)

    user: Mapped[User] = relationship(init=False, lazy="selectin")


class Sandbox(Base):
    """Durable user-facing sandbox whose compute can be replaced."""

    __tablename__ = "sandboxes"
    __table_args__ = {"comment": "Durable user-facing sandbox environments"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_templates.id", ondelete="RESTRICT"),
        index=True,
    )
    filesystem_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_filesystems.id", ondelete="RESTRICT"),
        index=True,
    )
    provider_kind: Mapped[SandboxProviderKind] = mapped_column(String(32), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[SandboxStatus] = mapped_column(
        String(32),
        default=SandboxStatus.INACTIVE,
        server_default=SandboxStatus.INACTIVE.value,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    status_reason: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    current_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(default=None, nullable=True)
    current_compute_id: Mapped[uuid.UUID | None] = mapped_column(default=None, nullable=True)
    exposed_urls: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default_factory=list)
    idle_timeout_seconds: Mapped[int | None] = mapped_column(default=None, nullable=True)
    max_lifetime_seconds: Mapped[int | None] = mapped_column(default=None, nullable=True)
    last_activity_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    last_activated_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    last_deactivated_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    delete_started_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TZ, init=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    filesystem: Mapped[SandboxFilesystem] = relationship(init=False, lazy="selectin")
    template: Mapped[SandboxTemplate] = relationship(init=False, lazy="selectin")
    user: Mapped[User] = relationship(init=False, lazy="selectin")


class SandboxSnapshot(Base):
    """User-visible named pin of a Fusey filesystem generation."""

    __tablename__ = "sandbox_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "filesystem_id",
            "generation",
            "name",
            name="uq_sandbox_snapshots_filesystem_generation_name",
        ),
        {"comment": "Named Fusey filesystem generation snapshots"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    filesystem_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sandbox_filesystems.id", ondelete="CASCADE"),
        index=True,
    )
    storage_kind: Mapped[SandboxStorageKind] = mapped_column(String(32), index=True)
    generation: Mapped[str] = mapped_column(String(255), index=True)
    snapshot_artifact: Mapped[SandboxSnapshotArtifact] = mapped_column(
        DiscriminatedUnionJSON(SandboxSnapshotArtifact),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, default=None, nullable=True)
    source_sandbox_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sandboxes.id", ondelete="SET NULL"),
        default=None,
        nullable=True,
        index=True,
    )
    status: Mapped[SandboxSnapshotStatus] = mapped_column(
        String(32),
        default=SandboxSnapshotStatus.READY,
        server_default=SandboxSnapshotStatus.READY.value,
        index=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TZ, init=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    filesystem: Mapped[SandboxFilesystem] = relationship(init=False, lazy="selectin")
    source_sandbox: Mapped[Sandbox | None] = relationship(init=False, lazy="selectin")
    user: Mapped[User] = relationship(init=False, lazy="selectin")


class SandboxCompute(Base):
    """Internal compute instance that can be attached to one sandbox."""

    __tablename__ = "sandbox_computes"
    __table_args__ = {"comment": "Internal replaceable sandbox compute attachments"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    provider_kind: Mapped[SandboxProviderKind] = mapped_column(String(32), index=True)
    status: Mapped[SandboxComputeStatus] = mapped_column(String(32), index=True)
    runtime_state: Mapped[SandboxRuntimeState | None] = mapped_column(
        DiscriminatedUnionJSON(SandboxRuntimeState),
        default=None,
        nullable=True,
    )
    server_state: Mapped[SandboxServerState | None] = mapped_column(
        DiscriminatedUnionJSON(SandboxServerState),
        default=None,
        nullable=True,
    )
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sandbox_templates.id", ondelete="SET NULL"),
        default=None,
        nullable=True,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sandboxes.id", ondelete="SET NULL"),
        default=None,
        nullable=True,
        index=True,
    )
    mount_lease_id: Mapped[uuid.UUID | None] = mapped_column(default=None, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(_TZ, init=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    terminated_at: Mapped[datetime | None] = mapped_column(_TZ, default=None, nullable=True)


__all__ = [
    "DiscriminatedUnionJSON",
    "DockerSandboxRuntimeState",
    "DockerSandboxTemplateSpec",
    "FuseySandboxSnapshotArtifact",
    "FuseySandboxStorageSpec",
    "OpenHandsAgentServerSpec",
    "OpenHandsAgentServerState",
    "Sandbox",
    "SandboxCompute",
    "SandboxComputeStatus",
    "SandboxFilesystem",
    "SandboxFilesystemStatus",
    "SandboxProviderKind",
    "SandboxResourceLimits",
    "SandboxRuntimeState",
    "SandboxServerSpec",
    "SandboxServerState",
    "SandboxSnapshot",
    "SandboxSnapshotArtifact",
    "SandboxSnapshotStatus",
    "SandboxStatus",
    "SandboxStorageKind",
    "SandboxStorageSpec",
    "SandboxTemplate",
    "SandboxTemplateSpec",
]
