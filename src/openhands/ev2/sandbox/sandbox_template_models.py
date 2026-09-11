"""ORM model for persisted sandbox templates.

A :class:`SandboxTemplate` is a DB-backed, provider-neutral description of how
to create a sandbox: the Docker/K8s image tag, lifecycle knobs, exposed ports,
env vars, and workspace configuration. Templates are mutable (unlike the prior
image-inventory model) so they can be updated without a redeploy.

The ``id`` is a UUID (not the image name) so the image tag can change without
orphaning existing :class:`SandboxConfig` foreign keys. The
``docker_image_tag`` is what the sandbox service pulls/uses at boot time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openhands.ev2.db import Base
from openhands.ev2.sandbox.sandbox_models import ExposedPort

if TYPE_CHECKING:
    from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig

_TZ = DateTime(timezone=True)


class SandboxTemplate(Base):
    """A DB-backed sandbox template.

    Carries everything the sandbox service needs to boot a sandbox: the image
    tag, lifespan knobs, exposed ports, env vars, and snapshot configuration.
    The ``meta`` JSONB column holds provider-specific hints the service may
    consume (e.g. K8s annotations, Docker labels).
    """

    __tablename__ = "sandbox_templates"
    __table_args__ = {"comment": "DB-backed sandbox templates (mutable, provider-neutral)"}  # noqa: RUF012

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    docker_image_tag: Mapped[str] = mapped_column(
        String(1024),
        comment="Image reference the sandbox service pulls/uses (e.g. ghcr.io/org/agent-server:latest).",
    )
    delete_after_idle_seconds: Mapped[int | None] = mapped_column(
        Integer,
        default=None,
        nullable=True,
        comment="Idle seconds before the lifecycle sweep deletes a sandbox derived from this template.",
    )
    in_container_user_id: Mapped[int | None] = mapped_column(
        Integer,
        default=None,
        nullable=True,
    )
    in_container_group_id: Mapped[int | None] = mapped_column(
        Integer,
        default=None,
        nullable=True,
    )
    max_memory: Mapped[int | None] = mapped_column(
        BigInteger,
        default=None,
        nullable=True,
        comment="Memory limit in bytes applied to the sandbox container (Docker and K8s).",
    )
    exposed_ports: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="Named container ports exposed to the host (max 100 items).",
    )
    env_vars: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Environment variables injected into the sandbox (max 4k chars serialized).",
    )
    working_dir: Mapped[str] = mapped_column(
        String(1024),
        default="/home/openhands",
    )
    snapshot_dirs: Mapped[list[str]] = mapped_column(
        JSONB,
        default_factory=list,
        comment="Workspace directories included in a snapshot.",
    )
    snapshot_on_deactivate: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default="false",
    )
    meta: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default_factory=dict,
        comment="Provider-specific hints consumed by the sandbox service (max 4k chars serialized).",
    )
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )

    sandbox_configs: Mapped[list[SandboxConfig]] = relationship(
        init=False,
        back_populates="sandbox_template",
        passive_deletes=True,
    )

    def to_exposed_ports(self) -> list[ExposedPort]:
        """Materialize the JSONB ``exposed_ports`` list into typed models."""
        return [ExposedPort(**p) for p in self.exposed_ports]
